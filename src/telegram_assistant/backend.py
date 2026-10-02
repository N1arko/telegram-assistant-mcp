"""Telethon adapter: only explicit reads and a guarded plain-text send."""
from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass
from .security import Denied


class _PageBoundary(Exception):
    pass


class _DialogBudget:
    """Per-listing proxy: at most one bounded catalogue RPC per tool call."""
    def __init__(self, backend):
        self.backend = backend
        self.remaining = 0
        self.limit = 1
        self.scanned = 0
        self.terminal = False
        self.truncated = False
    def __getattr__(self, name):
        return getattr(self.backend.client, name)
    async def __call__(self, request):
        from telethon import functions, types
        if not isinstance(request, functions.messages.GetDialogsRequest):
            raise Denied('unexpected_dialog_rpc')
        if self.remaining <= 0:
            raise _PageBoundary
        self.remaining -= 1
        request.limit = self.limit
        await self.backend.activate()
        result = await self.backend.client(request)
        if not isinstance(result, (types.messages.Dialogs, types.messages.DialogsSlice)):
            raise Denied('invalid_dialog_response')
        # Some API pages may also contain pinned entries. Hard-cap processing
        # rather than accepting an unexpectedly huge response vector.
        if any(len(getattr(result, name)) > 200 for name in ('dialogs','messages','users','chats')):
            raise Denied('dialog_batch_overflow')
        if len(result.dialogs) > 5000 - self.scanned:
            result.dialogs = result.dialogs[:5000 - self.scanned]
            self.truncated = True
        self.scanned += len(result.dialogs)
        self.terminal = not self.truncated and (not isinstance(result, types.messages.DialogsSlice) or len(result.dialogs) < request.limit)
        return result


@dataclass
class DialogListing:
    iterator: object
    budget: _DialogBudget
    archived: bool | None
    exhausted: bool = False
    truncated: bool = False


class TelethonBackend:
    def __init__(self, client, *, activate=None, read_only_broadcast_channel=None):
        self.client = client
        self.peers = OrderedDict()
        self.peer_seen = {}
        self._activate = activate
        # One immutable (marked_peer_id, exact_username) exception to the
        # personal/group-only surface. Production wires exactly one owner-
        # verified channel here; a missing value keeps the old behavior.
        self.read_only_broadcast_channel = read_only_broadcast_channel

    async def activate(self):
        if self._activate is not None:
            await self._activate()

    @staticmethod
    def kind(entity):
        from telethon.tl.types import User, Chat, Channel
        if isinstance(entity, User):
            return "user"
        if isinstance(entity, Chat) or (isinstance(entity, Channel) and (entity.megagroup or entity.gigagroup)):
            return "group"
        if isinstance(entity, Channel) and entity.broadcast:
            return "broadcast_channel"
        return "channel"

    def _is_allowed_broadcast(self, target, entity):
        if entity is None or self.read_only_broadcast_channel is None:
            return False
        allowed_peer_id, allowed_username = self.read_only_broadcast_channel
        username = getattr(entity, "username", None)
        return (target == allowed_peer_id and self.kind(entity) == "broadcast_channel" and
                isinstance(username, str) and username.casefold() == allowed_username.casefold() and
                getattr(entity, "creator", False) is True)

    def start_dialogs(self, archived):
        # Retain the pinned SDK iterator's offsets/seen set, but constrain each
        # catalogue fetch through a per-listing proxy. Never collect all dialogs.
        budget = _DialogBudget(self)
        iterator = self.client.iter_dialogs(limit=None, archived=archived).__aiter__()
        iterator.client = budget
        return DialogListing(iterator, budget, archived)

    def _remember(self, entity):
        from telethon.utils import get_peer_id
        target = get_peer_id(entity)
        self.peers[target] = entity
        self.peers.move_to_end(target)
        self.peer_seen[target] = time.monotonic()
        while len(self.peers) > 5000:
            old, _ = self.peers.popitem(last=False)
            self.peer_seen.pop(old, None)
        return target

    @staticmethod
    def _scrub(iterator):
        # SDK Dialog objects contain last-message/draft text. Offsets have
        # already been calculated; retain metadata/entities, never these texts.
        for item in iterator.buffer or ():
            item.message = None
            item.draft = None
            if hasattr(item.dialog, 'draft'):
                item.dialog.draft = None

    async def dialog_page(self, state, limit):
        from telethon.utils import get_peer_id
        rows = []
        state.budget.remaining = 1
        state.budget.limit = min(limit, 5000 - state.budget.scanned)
        if state.exhausted or state.budget.limit <= 0:
            state.truncated |= not state.exhausted
            return {'rows': [], 'done': True, 'truncated': state.truncated}
        # Limit consumed raw entries too. Excluded broadcast/unknown records
        # cannot trigger an unbounded fill-the-page loop.
        for _ in range(limit):
            try:
                dialog = await state.iterator.__anext__()
            except _PageBoundary:
                break
            except StopAsyncIteration:
                state.exhausted = True
                state.truncated |= not state.budget.terminal
                break
            finally:
                self._scrub(state.iterator)
            entity = dialog.entity
            kind = self.kind(entity)
            target = get_peer_id(entity)
            if (kind not in {'user','group'} and not self._is_allowed_broadcast(target, entity)) or (
                    state.archived is not None and bool(dialog.archived) != state.archived):
                continue
            target = self._remember(entity)
            title = getattr(entity, "title", None) or " ".join(
                x for x in (getattr(entity, "first_name", None), getattr(entity, "last_name", None)) if x)
            rows.append({"peer_id": target, "type": kind, "title": title,
                         "archived": bool(dialog.archived), "unread": dialog.unread_count or 0})
        if state.iterator.left <= 0:
            state.exhausted = True
        state.truncated |= state.budget.truncated
        if state.budget.scanned >= 5000 and not state.exhausted:
            state.truncated = True
        return {'rows': rows, 'done': state.exhausted or state.truncated, 'truncated': state.truncated}

    async def resolve(self, target):
        from telethon import functions, types
        from telethon.utils import get_peer_id
        # A marked Channel ID can identify a supergroup as well as a broadcast.
        # Cached broadcasts can be rejected before activation; unknown IDs use
        # the existing bounded membership lookup before their type is trusted.
        entity = self.peers.get(target)
        fresh = entity is not None and time.monotonic() - self.peer_seen.get(target, 0) <= 300
        if entity is not None and self.kind(entity) not in {'user','group'} and not self._is_allowed_broadcast(target, entity):
            raise Denied('peer_not_in_dialogs')
        await self.activate()
        if not fresh:
            # Targeted membership check. History/search never cause a hidden
            # complete catalogue scan, including for a peer from an older page.
            try:
                resolved = await self.client.get_input_entity(target)
            except (ValueError, TypeError):
                raise Denied('peer_not_in_dialogs') from None
            result = await self.client(functions.messages.GetPeerDialogsRequest([types.InputDialogPeer(resolved)]))
            entities = {get_peer_id(e): e for e in [*result.users, *result.chats]}
            matching = [d for d in result.dialogs if get_peer_id(d.peer) == target and getattr(d,'top_message',0) > 0]
            entity = entities.get(target)
            kind = self.kind(entity) if entity is not None else None
            if (not matching or entity is None or
                    (kind not in {'user','group'} and not self._is_allowed_broadcast(target, entity))):
                raise Denied('peer_not_in_dialogs')
            self._remember(entity)
        else:
            resolved = await self.client.get_input_entity(entity)
        if ((isinstance(resolved, types.InputPeerSelf) and not getattr(entity, 'is_self', False)) or
                (not isinstance(resolved, types.InputPeerSelf) and get_peer_id(resolved) != target)):
            raise Denied("peer_mismatch")
        # Resolve entity by stable ID; never username/phone/fuzzy matching.
        kind = self.kind(entity)
        if kind not in {'user','group'} and not self._is_allowed_broadcast(target, entity):
            raise Denied('peer_not_in_dialogs')
        return target, kind

    async def is_human_user(self, target):
        """Return true only for a resolved, non-bot, non-self Telegram user."""
        entity = self.peers.get(target)
        return (entity is not None and self.kind(entity) == "user" and
                not getattr(entity, "bot", False) and not getattr(entity, "is_self", False) and
                not getattr(entity, "min", False) and
                not getattr(entity, "deleted", False))

    async def verify_first_inbound(self, target, message_id):
        """Bind first-contact eligibility to a real inbound message and current oldest history.

        Telegram cannot reveal messages that were deleted remotely. This checks
        only currently available history and fails closed if either lookup is
        absent or malformed.
        """
        from telethon.utils import get_peer_id
        entity = self.peers.get(target)
        if (entity is None or self.kind(entity) != "user" or
                getattr(entity, "bot", False) or getattr(entity, "is_self", False) or
                getattr(entity, "min", False) or get_peer_id(entity) != target or
                getattr(entity, "deleted", False)):
            return False
        message = await self.client.get_messages(entity, ids=message_id)
        if (message is None or message.id != message_id or getattr(message, "out", True) or
                getattr(message, "sender_id", None) != entity.id):
            return False
        earliest = await self.client.get_messages(entity, limit=1, reverse=True)
        if not isinstance(earliest, (list, tuple)) or len(earliest) != 1:
            return False
        first = earliest[0]
        return (first is not None and first.id == message_id and
                not getattr(first, "out", True) and getattr(first, "sender_id", None) == entity.id)

    @staticmethod
    def record(message):
        from telethon.utils import get_peer_id
        reply = getattr(message, "reply_to", None)
        reply_peer = getattr(reply, "reply_to_peer_id", None)
        return {"id": message.id, "text": getattr(message, "message", "") or "",
                "date": message.date.isoformat() if message.date else None,
                "sender_id": message.sender_id, "has_media": message.media is not None,
                "reply_to": getattr(reply, "reply_to_msg_id", None),
                "reply_peer_id": get_peer_id(reply_peer) if reply_peer else None}

    async def history(self, target, *, limit, before_id=None, query=None):
        await self.activate()
        kwargs = {"limit": limit, "offset_id": before_id or 0}
        if query is not None:
            kwargs["search"] = query
        result = await self.client.get_messages(self.peers[target], **kwargs)
        return [self.record(m) for m in result if m is not None]

    async def message(self, target, message_id):
        await self.activate()
        message = await self.client.get_messages(self.peers[target], ids=message_id)
        return self.record(message) if message else None

    async def around(self, target, message_id, radius):
        await self.activate()
        if radius == 0:
            return [], []
        before = await self.client.get_messages(self.peers[target], limit=radius, max_id=message_id)
        after = await self.client.get_messages(self.peers[target], limit=radius, min_id=message_id, reverse=True)
        return [self.record(m) for m in before], [self.record(m) for m in after]

    async def send(self, target, text, reply_to):
        await self.activate()
        result = await self.client.send_message(self.peers[target], text, parse_mode=None,
                                                link_preview=False, reply_to=reply_to)
        return result.id
