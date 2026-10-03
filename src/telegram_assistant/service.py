"""Dependency-free restricted service, injectable backend for offline testing."""
from __future__ import annotations

import asyncio
import json
import math
import secrets
import time
from collections import OrderedDict
from contextvars import ContextVar
from pathlib import Path

from .security import Denied, Policy, Quotas, RateGate, integer, peer_id as validate_peer_id
from .media import (ImageResult, MAX_AUDIO_INPUT_BYTES, MAX_IMAGE_PREVIEW_BYTES,
                    MAX_IMAGE_INPUT_BYTES, MAX_MEDIA_RESPONSE_BYTES, MEDIA_TIMEOUT_SECONDS, MediaCache,
                    MAX_TRANSCRIPT_CHARS, TranscriptionConfig, prepare_audio, preview_image,
                    sniff_audio_kind, temporary_media_dir)

SCOPES: ContextVar[frozenset[str]] = ContextVar("telegram_assistant_scopes", default=frozenset())
MAX_BYTES = 48 * 1024


def clip(value, limit=200):
    text = str(value or "")
    return text[:limit], len(text) > limit


def encode_response(payload):
    # Remove whole tail records if JSON exceeds budget; always return a cursor
    # at the last emitted message rather than skipping unseen records.
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def wire_size(payload):
    # Account for escaping when compact JSON is carried in MCP TextContent,
    # plus a conservative JSON-RPC envelope allowance.
    body = {"content": [{"type": "text", "text": encode_response(payload).decode("utf-8")}],
            "isError": bool(payload.get("error"))}
    return len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 256


def bounded(payload):
    if wire_size(payload) > MAX_BYTES:
        raise Denied("response_too_large")
    return payload


class Service:
    def __init__(self, backend, policy: Policy | None = None, quotas: Quotas | None = None,
                 *, gate=None, clock=time.time, read_only_broadcast_channel=None,
                 transcription: TranscriptionConfig | None = None, transcriber=None,
                 media_cache=None):
        self.backend = backend
        self.policy = policy or Policy()
        self.quotas = quotas
        self.gate = gate or RateGate()
        self.clock = clock
        self.read_only_broadcast_channel = read_only_broadcast_channel
        self.transcription = transcription or TranscriptionConfig()
        self.transcriber = transcriber
        self.media_cache = media_cache or MediaCache()
        self.lock = asyncio.Lock()
        self.snapshots = OrderedDict()
        self.cursors = OrderedDict()

    async def invoke(self, operation, *args, **kwargs):
        # Tool annotations are hints, not authorization.
        if "telegram:read" not in SCOPES.get():
            return {"error": "unauthorized"}
        if operation not in {"list_dialogs", "get_history", "search_messages", "get_reply_context",
                             "view_photo", "transcribe_audio", "send_message"}:
            return {"error": "unknown_tool"}
        async with self.lock:
            try:
                self.gate.check()
                timeout = MEDIA_TIMEOUT_SECONDS if operation in {"view_photo", "transcribe_audio"} else 20
                result = await asyncio.wait_for(getattr(self, operation)(*args, **kwargs), timeout)
                if isinstance(result, ImageResult):
                    if (not isinstance(result.data, bytes) or result.mime_type != "image/jpeg" or
                            len(result.data) > MAX_IMAGE_PREVIEW_BYTES or
                            ((len(result.data) + 2) // 3) * 4 + 8192 > MAX_MEDIA_RESPONSE_BYTES):
                        raise Denied("image_preview_too_large")
                    return result
                return bounded(result)
            except Denied as exc:
                result = {"error": exc.code}
                if exc.retry_after is not None:
                    result["retry_after_seconds"] = exc.retry_after
                return result
            except TimeoutError:
                return {"error": "delivery_unknown" if operation == "send_message" else
                        ("media_timeout" if operation in {"view_photo", "transcribe_audio"} else "telegram_timeout")}
            except Exception as exc:
                # Inspect structured flood fields only; never return/log repr or args.
                if type(exc).__name__ in {"FloodWaitError", "SlowModeWaitError", "FloodPremiumWaitError"}:
                    seconds = max(1, int(getattr(exc, "seconds", 60)))
                    self.gate.flood(seconds)
                    return {"error": "telegram_rate_limited", "retry_after_seconds": seconds}
                return {"error": "delivery_unknown" if operation == "send_message" else
                        ("media_unavailable" if operation in {"view_photo", "transcribe_audio"} else "telegram_unavailable")}

    async def view_photo(self, peer_id, message_id):
        integer(message_id, 1, 2**31 - 1)
        target = await self._resolve(peer_id, allow_broadcast=True)
        key = ("photo", target, message_id)
        cached = self.media_cache.get(key)
        if cached is not None:
            return cached
        fetch = getattr(self.backend, "fetch_media_file", None)
        if fetch is None:
            raise Denied("media_unavailable")
        with temporary_media_dir() as directory:
            path = Path(directory) / "telegram-photo"
            await fetch(target, message_id, kind="photo", destination=path,
                        max_bytes=MAX_IMAGE_INPUT_BYTES)
            result = await preview_image(path)
        self.media_cache.put(key, result)
        return result

    @staticmethod
    def _check_audio_mime(kind, declared_mime):
        if declared_mime is None:
            return
        if not isinstance(declared_mime, str) or len(declared_mime) > 96:
            raise Denied("audio_mime_mismatch")
        declared = declared_mime.strip().lower().split(";", 1)[0]
        accepted = {
            "ogg-opus": {"audio/ogg", "application/ogg", "audio/opus", "application/octet-stream"},
            "mp3": {"audio/mpeg", "audio/mp3", "audio/x-mp3", "application/octet-stream"},
            "mp4": {"audio/mp4", "audio/m4a", "audio/x-m4a", "video/mp4", "application/octet-stream"},
            "wav": {"audio/wav", "audio/x-wav", "audio/wave", "application/octet-stream"},
            "webm": {"audio/webm", "video/webm", "application/octet-stream"},
        }
        if declared not in accepted[kind]:
            raise Denied("audio_mime_mismatch")

    async def transcribe_audio(self, peer_id, message_id):
        if self.transcription.provider != "openai" or self.transcriber is None:
            raise Denied("transcription_disabled")
        integer(message_id, 1, 2**31 - 1)
        target = await self._resolve(peer_id, allow_broadcast=True)
        key = ("transcript", target, message_id, "openai", self.transcription.max_duration_seconds)
        cached = self.media_cache.get(key)
        if cached is not None:
            text, transcript_truncated = cached
            return {"peer_id": target, "message_id": message_id, "transcript": text,
                    "transcript_truncated": transcript_truncated, "untrusted_content": True,
                    "provider": "openai", "cached": True}
        fetch = getattr(self.backend, "fetch_media_file", None)
        if fetch is None:
            raise Denied("media_unavailable")
        with temporary_media_dir() as directory:
            workdir = Path(directory)
            source = workdir / "telegram-audio"
            metadata = await fetch(target, message_id, kind="audio", destination=source,
                                   max_bytes=MAX_AUDIO_INPUT_BYTES)
            declared_duration = metadata.get("declared_duration") if isinstance(metadata, dict) else None
            if type(declared_duration) is not int or not 1 <= declared_duration <= self.transcription.max_duration_seconds:
                raise Denied("audio_too_long" if type(declared_duration) is int else "audio_duration_unavailable")
            actual_kind = sniff_audio_kind(source)
            self._check_audio_mime(actual_kind, metadata.get("declared_mime"))
            upload, filename, mime_type, duration = await prepare_audio(
                source, workdir, max_seconds=self.transcription.max_duration_seconds)
            if duration > self.transcription.max_duration_seconds:
                raise Denied("audio_too_long")
            billable_seconds = max(1, math.ceil(duration))
            if self.transcription.monthly_seconds:
                if self.quotas is None:
                    raise Denied("transcription_budget_unavailable")
                try:
                    self.quotas.reserve_transcription(
                        billable_seconds, self.transcription.monthly_seconds, self.clock())
                except Denied:
                    raise
                except Exception:
                    raise Denied("transcription_budget_unavailable") from None
            try:
                transcript = await self.transcriber.transcribe(
                    upload, filename=filename, mime_type=mime_type)
            except Denied:
                raise
            except Exception:
                raise Denied("transcription_provider_error") from None
        if not isinstance(transcript, str):
            raise Denied("transcription_provider_error")
        transcript_truncated = len(transcript) > MAX_TRANSCRIPT_CHARS
        transcript = transcript[:MAX_TRANSCRIPT_CHARS]
        self.media_cache.put(key, (transcript, transcript_truncated))
        return {"peer_id": target, "message_id": message_id, "transcript": transcript,
                "transcript_truncated": transcript_truncated, "untrusted_content": True,
                "provider": "openai", "cached": False}

    async def _resolve(self, target, *, allow_broadcast=False, return_type=False):
        target = validate_peer_id(target)
        allowed_peer_id = (self.read_only_broadcast_channel[0]
                           if self.read_only_broadcast_channel is not None else None)
        # This exact channel is read-only. Do not let send_message inherit the
        # read exception, even if a future technical send grant is introduced.
        if target == allowed_peer_id and not allow_broadcast:
            raise Denied("peer_mismatch")
        resolved = await self.backend.resolve(target)
        if resolved[0] != target:
            raise Denied("peer_mismatch")
        if target == allowed_peer_id:
            if not allow_broadcast or resolved[1] != "broadcast_channel":
                raise Denied("peer_mismatch")
            return (target, resolved[1]) if return_type else target
        if resolved[1] not in {"user", "group"}:
            raise Denied("peer_mismatch")
        return (target, resolved[1]) if return_type else target

    async def list_dialogs(self, archived=None, limit=20, cursor=None):
        integer(limit, 1, 50)
        if archived is not None and type(archived) is not bool:
            raise Denied("invalid_argument")
        now = self.clock()
        for key in list(self.snapshots):
            if self.snapshots[key]['expires'] <= now:
                del self.snapshots[key]
        if cursor is not None:
            if not isinstance(cursor, str) or len(cursor) > 128 or cursor not in self.cursors:
                raise Denied("invalid_cursor")
            snap, block_index, start, expected = self.cursors[cursor]
            if expected != archived or snap not in self.snapshots:
                raise Denied("cursor_expired_or_mismatched")
        else:
            # Reuse the cached prefix across chats instead of restarting a
            # Telegram catalogue scan on each initial request.
            snap = next((key for key, value in reversed(self.snapshots.items())
                         if value['archived'] == archived), None)
            if snap is None:
                snap = secrets.token_urlsafe(24)
                self.snapshots[snap] = {'expires': now + 300, 'archived': archived,
                                        'state': self.backend.start_dialogs(archived), 'blocks': []}
                while len(self.snapshots) > 4:
                    self.snapshots.popitem(last=False)
            block_index, start = 0, 0
        listing = self.snapshots[snap]
        if block_index == len(listing['blocks']):
            result = await self.backend.dialog_page(listing['state'], limit)
            rows = []
            allowed_peer_id = (self.read_only_broadcast_channel[0]
                               if self.read_only_broadcast_channel is not None else None)
            for d in result['rows']:
                configured_peer = d["peer_id"] == allowed_peer_id
                is_owner_broadcast = configured_peer and d["type"] == "broadcast_channel"
                if ((configured_peer and not is_owner_broadcast) or
                        (d["type"] not in {"user", "group"} and not is_owner_broadcast) or
                        (archived is not None and d["archived"] != archived)):
                    continue
                title, truncated = clip(d["title"])
                rows.append({"peer_id": d["peer_id"], "title": title, "title_truncated": truncated,
                             "type": "channel" if is_owner_broadcast else d["type"],
                             "archived": d["archived"], "unread": d["unread"]})
            listing['blocks'].append({'rows': rows, 'done': result['done'], 'truncated': result['truncated']})
        block = listing['blocks'][block_index]
        rows = block['rows']
        page = rows[start:start + limit]
        payload = {"dialogs": page, "next_cursor": None, "snapshot_expires_at": listing['expires'],
                   "listing_complete": False, "scan_truncated": block['truncated'],
                   "pagination_consistency": "cached_pages_stable_unfetched_live", "untrusted_content": True}
        while wire_size(payload) > MAX_BYTES - 64 and page:
            page.pop()
        end = start + len(page)
        if end < len(rows) or not block['done']:
            token = secrets.token_urlsafe(24)
            next_block, next_start = (block_index, end) if end < len(rows) else (block_index + 1, 0)
            self.cursors[token] = (snap, next_block, next_start, archived)
            payload["next_cursor"] = token
            while len(self.cursors) > 256:
                self.cursors.popitem(last=False)
        payload['listing_complete'] = payload['next_cursor'] is None and block['done'] and not block['truncated']
        return payload

    @staticmethod
    def _record(message, target):
        text, truncated = clip(message["text"], 2000)
        sender = message.get("sender_id")
        return {"peer_id": target, "message_id": message["id"], "sender_id": sender,
                "date": message.get("date"), "text": text, "text_truncated": truncated,
                "has_media": bool(message.get("has_media")), "reply_to": message.get("reply_to"),
                "reply_peer_id": message.get("reply_peer_id")}

    async def _messages(self, target, limit, before_id, query=None):
        integer(limit, 1, 50)
        if before_id is not None:
            integer(before_id, 1, 2**31 - 1)
        target = await self._resolve(target, allow_broadcast=True)
        messages = await self.backend.history(target, limit=limit + 1, before_id=before_id, query=query)
        page = messages[:limit]
        records = [self._record(m, target) for m in page]
        payload = {"messages": records, "next_before_id": None, "untrusted_content": True,
                   "order": "message_id_desc"}
        # Cursor is populated after fitting response; preserve room for it.
        while wire_size(payload) > MAX_BYTES - 64 and records:
            records.pop()
        has_more = len(messages) > len(records)
        if has_more and records:
            payload["next_before_id"] = records[-1]["message_id"]
        return payload

    async def get_history(self, peer_id, limit=20, before_id=None):
        return await self._messages(peer_id, limit, before_id)

    async def search_messages(self, peer_id, query, limit=20, before_id=None):
        if not isinstance(query, str) or not query.strip() or len(query) > 256:
            raise Denied("invalid_query")
        return await self._messages(peer_id, limit, before_id, query=query)

    async def get_reply_context(self, peer_id, message_id, radius=3):
        integer(message_id, 1, 2**31 - 1)
        integer(radius, 0, 10)
        target = await self._resolve(peer_id, allow_broadcast=True)
        message = await self.backend.message(target, message_id)
        if message is None:
            return {"error": "message_missing"}
        before, after = await self.backend.around(target, message_id, radius)
        records = [self._record(m, target) for m in sorted([*before, message, *after], key=lambda m: m["id"])]
        reply = None
        reply_state = "none"
        if message.get("reply_to"):
            reply_peer = message.get("reply_peer_id")
            if reply_peer is not None and reply_peer != target:
                reply_state = "cross_peer_reference_only"
            else:
                replied = await self.backend.message(target, message["reply_to"])
                reply = self._record(replied, target) if replied else None
                reply_state = "available" if replied else "missing"
        payload = {"target_message_id": message_id, "messages": records, "replied_message": reply,
                   "reply_state": reply_state, "context_truncated": False, "untrusted_content": True}
        # Keep target and quote; trim outer context until bounded.
        while wire_size(payload) > MAX_BYTES and len(records) > 1:
            index = max((i for i, r in enumerate(records) if r["message_id"] != message_id),
                        key=lambda i: abs(records[i]["message_id"] - message_id))
            records.pop(index)
            payload["context_truncated"] = True
        return payload

    async def send_message(self, peer_id, text, reply_to=None, first_contact_message_id=None):
        target = validate_peer_id(peer_id)
        if reply_to is not None:
            integer(reply_to, 1, 2**31 - 1)
        if first_contact_message_id is not None:
            integer(first_contact_message_id, 1, 2**31 - 1)
        # A broad selector is only a candidate until peer class is resolved.
        # Explicit denies and default-deny still stop before contacting Telegram.
        candidates = self.policy.precheck(target, text, SCOPES.get(), self.clock())
        first_rules = tuple(g for g in candidates if g.first_contact)
        if first_contact_message_id is None:
            if first_rules and not any(not g.first_contact for g in candidates):
                raise Denied("first_contact_message_required")
        elif not first_rules or reply_to != first_contact_message_id:
            raise Denied("invalid_first_contact_reference")
        if self.quotas is None:
            raise Denied("send_denied")
        target, peer_type = await self._resolve(target, return_type=True)
        needs_human = peer_type == "user" or any(
            g.selector in {"all_human_dms", "first_contact"} for g in candidates)
        is_human = False
        if needs_human:
            check_human = getattr(self.backend, "is_human_user", None)
            is_human = bool(check_human and await check_human(target))
            if not is_human:
                raise Denied("peer_not_human")
        first_contact_verified = False
        if first_rules and first_contact_message_id is not None:
            verify = getattr(self.backend, "verify_first_inbound", None)
            try:
                first_contact_verified = bool(verify and await verify(target, first_contact_message_id))
            except Exception as exc:
                if type(exc).__name__ in {"FloodWaitError", "SlowModeWaitError", "FloodPremiumWaitError"}:
                    raise
                raise Denied("first_contact_unavailable") from None
            if not first_contact_verified:
                raise Denied("first_contact_unverified")
        if reply_to is not None and not first_contact_verified and await self.backend.message(target, reply_to) is None:
            raise Denied("reply_target_missing")
        # Recheck expiry after async resolution and reserve transactionally.
        grant = self.policy.authorize(target, text, SCOPES.get(), self.clock(),
                                      peer_type=peer_type, is_human=is_human,
                                      first_contact_verified=first_contact_verified)
        self.quotas.reserve(grant, self.clock(),
                            first_contact_message_id=first_contact_message_id if grant.first_contact else None)
        try:
            result = await self.backend.send(target, text, reply_to)
        except BaseException:
            if grant.first_contact and first_contact_message_id is not None:
                self.quotas.finish_first_contact(target, first_contact_message_id, "unknown")
            raise
        if grant.first_contact and first_contact_message_id is not None:
            self.quotas.finish_first_contact(target, first_contact_message_id, "sent")
        return {"sent": True, "peer_id": target, "message_id": result}
