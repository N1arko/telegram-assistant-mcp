"""One explicitly configured owner broadcast channel, never a channel wildcard."""
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from telethon import functions, types
from telethon.utils import get_peer_id

from telegram_assistant.backend import TelethonBackend
from telegram_assistant.security import Denied, RateGate
from telegram_assistant.service import SCOPES, Service


def channel(channel_id, username='owner_channel', *, creator=True, broadcast=True, megagroup=False):
    return types.Channel(id=channel_id, access_hash=channel_id * 10, title='channel',
                         photo=None, date=None, creator=creator, broadcast=broadcast,
                         megagroup=megagroup, gigagroup=False, username=username)


class FakeBackend:
    def __init__(self, allowed_peer_id, other_peer_id):
        self.allowed_peer_id = allowed_peer_id
        self.other_peer_id = other_peer_id
        self.history_calls = []

    def start_dialogs(self, archived):
        return None

    async def dialog_page(self, state, limit):
        return {'rows': [
            {'peer_id': 42, 'type': 'user', 'title': 'personal', 'archived': False, 'unread': 0},
            {'peer_id': -77, 'type': 'group', 'title': 'group', 'archived': False, 'unread': 0},
            {'peer_id': self.allowed_peer_id, 'type': 'user', 'title': 'type mismatch',
             'archived': False, 'unread': 0},
            {'peer_id': self.allowed_peer_id, 'type': 'broadcast_channel', 'title': 'owner channel',
             'archived': False, 'unread': 0},
            {'peer_id': self.other_peer_id, 'type': 'broadcast_channel', 'title': 'other channel',
             'archived': False, 'unread': 0}], 'done': True, 'truncated': False}

    async def resolve(self, target):
        if target in {self.allowed_peer_id, self.other_peer_id}:
            return target, 'broadcast_channel'
        if target == -77:
            return target, 'group'
        return target, 'user'

    async def history(self, target, *, limit, before_id, query):
        self.history_calls.append((target, limit, before_id, query))
        return [{'id': 1, 'text': '', 'date': None, 'sender_id': None,
                 'has_media': False, 'reply_to': None, 'reply_peer_id': None}]

    async def message(self, target, message_id):
        return None

    async def around(self, target, message_id, radius):
        return [], []


class BackendChannelGuardTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_exact_username_and_creator_match_the_configured_peer(self):
        owned = channel(123)
        peer_id = get_peer_id(owned)
        client = SimpleNamespace(get_input_entity=AsyncMock(
            return_value=types.InputPeerChannel(owned.id, owned.access_hash)))
        activate = AsyncMock()
        backend = TelethonBackend(client, activate=activate,
                                  read_only_broadcast_channel=(peer_id, 'owner_channel'))
        backend._remember(owned)
        self.assertEqual(await backend.resolve(peer_id), (peer_id, 'broadcast_channel'))
        activate.assert_awaited_once()
        client.get_input_entity.assert_awaited_once_with(owned)

        for invalid in (channel(124, 'other_channel'), channel(125, creator=False)):
            invalid_peer_id = get_peer_id(invalid)
            guarded = TelethonBackend(client, activate=AsyncMock(),
                                      read_only_broadcast_channel=(invalid_peer_id, 'owner_channel'))
            guarded._remember(invalid)
            with self.assertRaises(Denied):
                await guarded.resolve(invalid_peer_id)
            guarded._activate.assert_not_awaited()

    async def test_cached_other_broadcast_is_denied_before_activation_or_rpc(self):
        owned_peer_id = get_peer_id(channel(123))
        other = channel(124, 'other_channel')
        other_peer_id = get_peer_id(other)
        client = SimpleNamespace(get_input_entity=AsyncMock())
        activate = AsyncMock()
        backend = TelethonBackend(client, activate=activate,
                                  read_only_broadcast_channel=(owned_peer_id, 'owner_channel'))
        backend._remember(other)
        with self.assertRaises(Denied):
            await backend.resolve(other_peer_id)
        activate.assert_not_awaited()
        client.get_input_entity.assert_not_awaited()

    async def test_cold_owner_channel_uses_only_targeted_membership_rpc(self):
        owned = channel(123)
        peer_id = get_peer_id(owned)

        class TargetClient:
            def __init__(self):
                self.requests = []

            async def get_input_entity(self, target):
                return types.InputPeerChannel(owned.id, owned.access_hash)

            async def __call__(self, request):
                self.requests.append(request)
                dialog = types.Dialog(
                    peer=types.PeerChannel(owned.id), top_message=1, read_inbox_max_id=0,
                    read_outbox_max_id=0, unread_count=0, unread_mentions_count=0,
                    unread_reactions_count=0, unread_poll_votes_count=0,
                    notify_settings=types.PeerNotifySettings())
                return SimpleNamespace(dialogs=[dialog], users=[], chats=[owned])

        client = TargetClient()
        backend = TelethonBackend(client, read_only_broadcast_channel=(peer_id, 'owner_channel'))
        self.assertEqual(await backend.resolve(peer_id), (peer_id, 'broadcast_channel'))
        self.assertEqual(len(client.requests), 1)
        self.assertIsInstance(client.requests[0], functions.messages.GetPeerDialogsRequest)

    async def test_cold_and_cached_supergroups_keep_the_existing_read_path(self):
        group = channel(126, 'group', creator=False, megagroup=True, broadcast=False)
        target = get_peer_id(group)
        request = types.InputPeerChannel(group.id, group.access_hash)
        dialog = SimpleNamespace(peer=types.PeerChannel(group.id), top_message=1)
        rpc = AsyncMock(return_value=SimpleNamespace(dialogs=[dialog], users=[], chats=[group]))

        class Client:
            get_input_entity = AsyncMock(return_value=request)
            async def __call__(self, request):
                return await rpc(request)

        backend = TelethonBackend(Client(), read_only_broadcast_channel=(get_peer_id(channel(123)), 'owner_channel'))
        self.assertEqual(await backend.resolve(target), (target, 'group'))
        self.assertEqual(await backend.resolve(target), (target, 'group'))
        rpc.assert_awaited_once()

    async def test_uncached_other_broadcast_is_denied_after_bounded_membership_lookup(self):
        other = channel(124, 'other_channel')
        target = get_peer_id(other)
        rpc = AsyncMock(return_value=SimpleNamespace(
            dialogs=[SimpleNamespace(peer=types.PeerChannel(other.id), top_message=1)],
            users=[], chats=[other]))

        class Client:
            get_input_entity = AsyncMock(return_value=types.InputPeerChannel(other.id, other.access_hash))
            async def __call__(self, request):
                return await rpc(request)

        backend = TelethonBackend(Client(), read_only_broadcast_channel=(get_peer_id(channel(123)), 'owner_channel'))
        with self.assertRaises(Denied):
            await backend.resolve(target)
        self.assertNotIn(target, backend.peers)
        rpc.assert_awaited_once()

    async def test_supergroups_remain_groups_and_broadcasts_are_distinct(self):
        self.assertEqual(TelethonBackend.kind(types.User(id=42)), 'user')
        group = types.Chat(id=9, title='group', photo=None, participants_count=2,
                           date=None, version=1)
        self.assertEqual(TelethonBackend.kind(group), 'group')
        self.assertEqual(TelethonBackend.kind(channel(123, megagroup=True, broadcast=False)), 'group')
        self.assertEqual(TelethonBackend.kind(channel(124)), 'broadcast_channel')


class ServiceChannelGuardTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.context = SCOPES.set(frozenset({'telegram:read'}))
        self.allowed_peer_id = get_peer_id(channel(123))
        self.other_peer_id = get_peer_id(channel(124, 'other_channel'))
        self.configured = (self.allowed_peer_id, 'owner_channel')
        self.backend = FakeBackend(self.allowed_peer_id, self.other_peer_id)
        self.service = Service(self.backend, gate=RateGate(limit=1000),
                               read_only_broadcast_channel=self.configured)

    def tearDown(self):
        SCOPES.reset(self.context)

    async def test_list_keeps_personal_groups_and_only_exact_broadcast(self):
        result = await self.service.invoke('list_dialogs', limit=50)
        self.assertEqual([row['peer_id'] for row in result['dialogs']],
                         [42, -77, self.allowed_peer_id])
        self.assertEqual([row['type'] for row in result['dialogs']],
                         ['user', 'group', 'channel'])

    async def test_reads_allow_exact_channel_but_no_other_broadcast(self):
        for peer_id in (42, -77, self.allowed_peer_id):
            result = await self.service.invoke('get_history', peer_id=peer_id, limit=1)
            self.assertNotIn('error', result)
        result = await self.service.invoke('get_history', peer_id=self.other_peer_id, limit=1)
        self.assertEqual(result, {'error': 'peer_mismatch'})
        self.assertEqual([row[0] for row in self.backend.history_calls],
                         [42, -77, self.allowed_peer_id])

    async def test_channel_read_exception_is_not_available_to_the_send_path(self):
        with self.assertRaises(Denied):
            await self.service._resolve(self.allowed_peer_id)
