"""Forum discovery and sending checks use only synthetic Telegram objects."""
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

from telethon import functions, types

from telegram_assistant.backend import TelethonBackend
from telegram_assistant.security import Denied, Grant, Policy, Quotas, RateGate
from telegram_assistant.service import SCOPES, Service
from test_service import Fake


def topic(peer_id, topic_id=14381, **changes):
    return {"peer_id": peer_id, "topic_id": topic_id, "title": "Istina",
            "closed": False, "hidden": False, "deleted": False,
            "top_message_id": 19938, "date": None, **changes}


class ForumServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.quotas = Quotas(Path(self.tmp.name) / "quota.sqlite")
        self.fake = Fake()
        self.fake.peer_type = "group"
        self.fake.forum = True
        self.fake.topics = {14381: topic(-99)}
        self.fake.send.return_value = 20000
        self.service = Service(self.fake, Policy([Grant(-99, None, 200, 2, 4)]),
                               self.quotas, gate=RateGate(limit=1000))
        self.context = SCOPES.set(frozenset({"telegram:read", "telegram:send"}))

    def tearDown(self):
        SCOPES.reset(self.context)
        self.quotas.close()
        self.tmp.cleanup()

    async def test_read_only_topic_identity_and_no_receipts(self):
        SCOPES.set(frozenset({"telegram:read"}))
        found = await self.service.invoke("get_forum_topic", peer_id=-99, topic_id=14381)
        self.assertEqual(found["topic"]["title"], "Istina")
        self.assertEqual(found["topic"]["peer_id"], -99)
        page = await self.service.invoke("list_forum_topics", peer_id=-99, limit=1)
        self.assertEqual(page["topics"][0]["topic_id"], 14381)
        self.fake.read_receipt.assert_not_awaited()
        self.fake.send.assert_not_awaited()

    async def test_reply_context_names_topic_when_root_message_is_missing(self):
        self.fake.items = [{"id": 19938, "text": "synthetic", "date": None,
                            "sender_id": 42, "has_media": False, "reply_to": 14381}]
        result = await self.service.invoke("get_reply_context", peer_id=-99,
                                           message_id=19938, radius=0)
        self.assertEqual(result["reply_state"], "missing")
        self.assertEqual(result["forum_topic"]["title"], "Istina")
        self.fake.read_receipt.assert_not_awaited()

    async def test_wrong_group_missing_deleted_and_invalid_offset(self):
        self.fake.topics[14381] = topic(-98)
        self.assertEqual((await self.service.invoke("get_forum_topic", peer_id=-99,
                          topic_id=14381))["error"], "topic_peer_mismatch")
        self.fake.topics.clear()
        self.assertEqual((await self.service.invoke("get_forum_topic", peer_id=-99,
                          topic_id=14381))["error"], "topic_missing")
        self.fake.topics[14381] = {"peer_id": -99, "topic_id": 14381, "deleted": True}
        self.assertTrue((await self.service.invoke("get_forum_topic", peer_id=-99,
                        topic_id=14381))["topic"]["deleted"])
        self.assertEqual((await self.service.invoke("list_forum_topics", peer_id=-99,
                          offset_topic=14381))["error"], "invalid_topic_offset")

    async def test_topic_address_checks_before_quota_or_send(self):
        attempts = lambda: self.quotas.db.execute("SELECT count(*) FROM attempts").fetchone()[0]
        for kwargs, code in [({}, "topic_id_required"),
                             ({"topic_id": 999}, "topic_missing"),
                             ({"topic_id": 14381, "reply_to": 19938}, "topic_reply_unsupported")]:
            self.assertEqual((await self.service.invoke("send_message", peer_id=-99,
                             text="synthetic", **kwargs))["error"], code)
        self.fake.topics[14381] = topic(-99, closed=True)
        self.assertEqual((await self.service.invoke("send_message", peer_id=-99,
                          text="synthetic", topic_id=14381))["error"], "topic_unavailable")
        self.fake.topics[14381] = {"peer_id": -99, "topic_id": 14381, "deleted": True}
        self.assertEqual((await self.service.invoke("send_message", peer_id=-99,
                          text="synthetic", topic_id=14381))["error"], "topic_missing")
        self.assertEqual(attempts(), 0)
        self.fake.send.assert_not_awaited()

    async def test_valid_topic_root_send_and_unknown_result(self):
        result = await self.service.invoke("send_message", peer_id=-99, text="synthetic",
                                           topic_id=14381)
        self.assertEqual(result["topic_id"], 14381)
        self.fake.send.assert_awaited_once_with(-99, "synthetic", 14381)
        self.fake.send.return_value = None
        result = await self.service.invoke("send_message", peer_id=-99, text="synthetic",
                                           topic_id=14381)
        self.assertEqual(result, {"error": "delivery_unknown"})
        self.assertEqual((await self.service.invoke("send_message", peer_id=-99,
                          text="synthetic", topic_id=14381))["error"], "send_quota_exceeded")

    async def test_media_uses_same_verified_topic_root(self):
        item = {"media_type": "document", "data_base64": "JVBERi0xLjc="}
        result = await self.service.invoke("send_media", peer_id=-99,
                                           items=[item], topic_id=14381)
        self.assertEqual(result["topic_id"], 14381)
        self.assertEqual(self.fake.send_media_files.await_args.args[2], 14381)

    async def test_policy_scope_and_telegram_write_denial(self):
        SCOPES.set(frozenset({"telegram:read"}))
        self.assertEqual((await self.service.invoke("send_message", peer_id=-99,
                          text="synthetic", topic_id=14381))["error"], "send_scope_required")
        SCOPES.set(frozenset({"telegram:read", "telegram:send"}))
        self.service.policy = Policy(denies=[NS(peer_id=-99, active=lambda now: True)])
        self.assertEqual((await self.service.invoke("send_message", peer_id=-99,
                          text="synthetic", topic_id=14381))["error"], "send_policy_denied")
        self.service.policy = Policy([Grant(-99, None, 200, 2, 4)])
        class ChatWriteForbiddenError(Exception):
            pass
        self.fake.send.side_effect = ChatWriteForbiddenError("private details")
        self.assertEqual((await self.service.invoke("send_message", peer_id=-99,
                          text="synthetic", topic_id=14381)), {"error": "telegram_write_forbidden"})

    async def test_preflight_failure_does_not_claim_unknown_delivery(self):
        self.fake.forum_state = AsyncMock(side_effect=RuntimeError("private details"))
        result = await self.service.invoke("send_message", peer_id=-99,
                                           text="synthetic", topic_id=14381)
        self.assertEqual(result, {"error": "send_preflight_unavailable"})
        self.fake.send.assert_not_awaited()
        self.assertEqual(self.quotas.db.execute("SELECT count(*) FROM attempts").fetchone()[0], 0)

    async def test_unknown_forum_state_fails_closed_before_quota_or_send(self):
        self.fake.forum_state = AsyncMock(side_effect=Denied("forum_state_unavailable"))
        result = await self.service.invoke("send_message", peer_id=-99,
                                           text="synthetic", topic_id=14381)
        self.assertEqual(result, {"error": "forum_state_unavailable"})
        self.fake.send.assert_not_awaited()
        self.assertEqual(self.quotas.db.execute("SELECT count(*) FROM attempts").fetchone()[0], 0)

    async def test_missing_quota_store_is_distinct_from_recipient_denial(self):
        self.service.quotas = None
        self.assertEqual((await self.service.invoke("send_message", peer_id=-99,
                          text="synthetic", topic_id=14381))["error"], "send_quota_unavailable")
        self.fake.send.assert_not_awaited()


class ForumBackendTests(unittest.IsolatedAsyncioTestCase):
    async def test_forum_state_accepts_fresh_min_channel_flag(self):
        class Client:
            def __init__(self):
                self.call = AsyncMock()
            async def __call__(self, request):
                return await self.call(request)

        client = Client()
        backend = TelethonBackend(client)
        entity = types.Channel(id=99, title="Synthetic", photo=None, date=None,
                               megagroup=True, forum=False)
        peer_id = backend._remember(entity)
        fresh_min = types.Channel(id=99, title="Synthetic", photo=None, date=None,
                                  megagroup=True, forum=True, min=True)
        client.call.return_value = NS(chats=[fresh_min])

        self.assertTrue(await backend.forum_state(peer_id))
        self.assertIs(backend.peers[peer_id], fresh_min)
        self.assertIsInstance(client.call.await_args.args[0],
                              functions.channels.GetFullChannelRequest)

        fresh_min_nonforum = types.Channel(id=99, title="Synthetic", photo=None, date=None,
                                           megagroup=True, forum=False, min=True)
        client.call.return_value = NS(chats=[fresh_min_nonforum])
        self.assertFalse(await backend.forum_state(peer_id))

        gigagroup = types.Channel(id=100, title="Synthetic large group", photo=None, date=None,
                                  megagroup=False, gigagroup=True, forum=False)
        gigagroup_id = backend._remember(gigagroup)
        fresh_gigagroup = types.Channel(id=100, title="Synthetic large group", photo=None,
                                        date=None, megagroup=False, gigagroup=True, forum=False)
        client.call.return_value = NS(chats=[fresh_gigagroup])
        self.assertFalse(await backend.forum_state(gigagroup_id))

    async def test_forum_state_unknown_or_mismatched_entity_stays_denied(self):
        class Client:
            def __init__(self):
                self.call = AsyncMock()
            async def __call__(self, request):
                return await self.call(request)

        client = Client()
        backend = TelethonBackend(client)
        entity = types.Channel(id=99, title="Synthetic", photo=None, date=None,
                               megagroup=True, forum=True)
        peer_id = backend._remember(entity)

        for chats in ([], [types.Channel(id=98, title="Other", photo=None, date=None,
                                         megagroup=True, forum=True)]):
            client.call.return_value = NS(chats=chats)
            with self.assertRaises(Denied) as error:
                await backend.forum_state(peer_id)
            self.assertEqual(error.exception.code, "forum_state_unavailable")

    async def test_exact_topic_rpc_and_bounded_page_no_receipts(self):
        class Client:
            def __init__(self):
                self.call = AsyncMock()
                self.send_read_acknowledge = AsyncMock()
            async def __call__(self, request):
                return await self.call(request)
        client = Client()
        backend = TelethonBackend(client)
        group = types.Channel(id=99, title="Synthetic", photo=None, date=None,
                              megagroup=True, forum=True)
        peer_id = backend._remember(group)
        when = datetime(2026, 1, 1, tzinfo=timezone.utc)
        row = types.ForumTopic(id=14381, date=when, peer=types.PeerChannel(99),
                               title="Istina", icon_color=0, top_message=19938,
                               read_inbox_max_id=0, read_outbox_max_id=0, unread_count=0,
                               unread_mentions_count=0, unread_reactions_count=0,
                               unread_poll_votes_count=0, from_id=types.PeerUser(42),
                               notify_settings=types.PeerNotifySettings())
        client.call.return_value = NS(topics=[row], messages=[], count=1)
        found = await backend.forum_topic(peer_id, 14381)
        self.assertEqual((found["peer_id"], found["title"]), (peer_id, "Istina"))
        self.assertIsInstance(client.call.await_args.args[0],
                              functions.messages.GetForumTopicsByIDRequest)
        client.call.return_value = NS(topics=[row],
                                         messages=[NS(id=19938, date=when)], count=2)
        rows, offset, truncated = await backend.forum_topics(peer_id, limit=1)
        self.assertEqual(rows[0]["topic_id"], 14381)
        self.assertEqual(offset["offset_topic"], 14381)
        self.assertFalse(truncated)
        self.assertIsInstance(client.call.await_args.args[0],
                              functions.messages.GetForumTopicsRequest)
        rows, offset, truncated = await backend.forum_topics(peer_id, limit=1,
            offset_date=offset["offset_date"], offset_id=offset["offset_id"],
            offset_topic=offset["offset_topic"])
        request = client.call.await_args.args[0]
        self.assertEqual(request.offset_topic, 14381)
        self.assertEqual(request.offset_id, 19938)
        client.call.return_value = NS(topics=[row], messages=[], count=2)
        rows, offset, truncated = await backend.forum_topics(peer_id, limit=1)
        self.assertTrue(truncated)
        self.assertIsNone(offset)
        client.call.return_value = NS(topics=[], messages=[], count=2)
        rows, offset, truncated = await backend.forum_topics(peer_id, limit=1)
        self.assertEqual(rows, [])
        self.assertIsNone(offset)
        self.assertFalse(truncated)
        backend.peers[peer_id] = types.Channel(id=99, title="Synthetic", photo=None,
                                                date=None, megagroup=True, forum=False)
        client.call.return_value = NS(chats=[group])
        self.assertTrue(await backend.forum_state(peer_id))
        self.assertTrue(backend.is_forum_group(peer_id))
        self.assertIsInstance(client.call.await_args.args[0],
                              functions.channels.GetFullChannelRequest)
        client.send_read_acknowledge.assert_not_awaited()

    async def test_deleted_and_wrong_peer(self):
        deleted = TelethonBackend._topic(-99, types.ForumTopicDeleted(id=14381))
        self.assertTrue(deleted["deleted"])
        with self.assertRaises(Denied) as error:
            TelethonBackend._topic(-99, types.ForumTopic(
                id=14381, date=None, peer=types.PeerChannel(98), title="Other",
                icon_color=0, top_message=1, read_inbox_max_id=0,
                read_outbox_max_id=0, unread_count=0, unread_mentions_count=0,
                unread_reactions_count=0, unread_poll_votes_count=0,
                from_id=types.PeerUser(42), notify_settings=types.PeerNotifySettings()))
        self.assertEqual(error.exception.code, "topic_peer_mismatch")
