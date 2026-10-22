import unittest
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock

from telethon import types
from telethon.utils import get_peer_id

from telegram_assistant.backend import TelethonBackend
from telegram_assistant.security import Denied, RateGate
from telegram_assistant.service import SCOPES, Service, parse_channel_reference


def public_channel(channel_id=2206439398, username="niar42", *, broadcast=True, megagroup=False):
    return types.Channel(id=channel_id, access_hash=channel_id * 10, title="Niar",
                         photo=None, date=None, creator=True, broadcast=broadcast,
                         megagroup=megagroup, gigagroup=False, username=username)


def message(message_id, text=None):
    return SimpleNamespace(id=message_id, message=text if text is not None else f"post {message_id}",
                           date=datetime(2026, 10, 22, tzinfo=timezone.utc),
                           sender_id=None, media=None, reply_to=None, photo=None,
                           document=None, out=False)


class ChannelReferenceTests(unittest.TestCase):
    def test_accepts_usernames_and_public_post_links(self):
        self.assertEqual(parse_channel_reference("@niar42"), ("niar42", None))
        self.assertEqual(parse_channel_reference("https://t.me/niar42"), ("niar42", None))
        self.assertEqual(parse_channel_reference("https://t.me/s/niar42/123?single"),
                         ("niar42", 123))
        self.assertEqual(parse_channel_reference("https://telegram.me/niar42/123"),
                         ("niar42", 123))

    def test_rejects_invite_private_and_non_telegram_links(self):
        for reference in ("https://t.me/+invitehash", "https://t.me/c/2206439398/1",
                          "https://example.com/niar42", "http://t.me/niar42",
                          "https://t.me.evil/niar42", "https://t.me:443/niar42",
                          "https://user@t.me/niar42", "https://t.me/niar42/0",
                          "https://t.me/niar42/1/2"):
            with self.subTest(reference=reference), self.assertRaises(Denied):
                parse_channel_reference(reference)


class OnDemandChannelReadTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scope = SCOPES.set(frozenset({"telegram:read"}))

    async def asyncTearDown(self):
        SCOPES.reset(self.scope)

    async def test_username_page_is_bounded_and_reports_continuation(self):
        channel = public_channel()

        class Client:
            get_entity = AsyncMock(return_value=channel)

            def __init__(self):
                self.history_calls = []

            async def get_messages(self, entity, **kwargs):
                self.history_calls.append((entity, kwargs))
                return [message(30), message(29), message(28)]

        client = Client()
        backend = TelethonBackend(client)
        service = Service(backend, gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        result = await service.invoke("read_channel", reference="@niar42", limit=2)

        target = get_peer_id(channel)
        self.assertEqual(client.get_entity.await_args.args, ("@niar42",))
        self.assertEqual(len(client.history_calls), 1)
        self.assertEqual(client.history_calls[0][1],
                         {"limit": 3, "offset_id": 0})
        self.assertEqual([item["message_id"] for item in result["messages"]], [30, 29])
        self.assertEqual(result["peer_id"], target)
        self.assertEqual(result["next_before_id"], 29)
        self.assertFalse(result["complete"])
        self.assertTrue(result["incomplete"])

    async def test_public_post_link_fetches_only_that_post_without_membership_rpc(self):
        channel = public_channel()

        class Client:
            get_entity = AsyncMock(return_value=channel)

            def __init__(self):
                self.message_calls = []

            async def get_messages(self, entity, **kwargs):
                self.message_calls.append((entity, kwargs))
                return message(81)

        client = Client()
        backend = TelethonBackend(client)
        service = Service(backend, gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        result = await service.invoke("read_channel", reference="https://t.me/niar42/81")

        self.assertEqual([item["message_id"] for item in result["messages"]], [81])
        self.assertTrue(result["exact_post"])
        self.assertTrue(result["complete"])
        self.assertEqual(client.message_calls[0][1], {"ids": 81})
        # Client intentionally has no generic RPC method: resolver must not use
        # GetPeerDialogs or any join API for this explicit public read.
        self.assertEqual(len(client.message_calls), 1)

    async def test_long_exact_post_returns_bounded_chunks_with_text_cursor(self):
        channel = public_channel()
        full_text = "a" * 3998 + "🙂" * 5 + "tail"

        class Client:
            get_entity = AsyncMock(return_value=channel)

            def __init__(self):
                self.message_calls = []

            async def get_messages(self, entity, **kwargs):
                self.message_calls.append((entity, kwargs))
                return message(kwargs["ids"], full_text)

        client = Client()
        service = Service(TelethonBackend(client), gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        reference = "https://t.me/niar42/81"
        first = await service.invoke("read_channel", reference=reference)
        first_post = first["messages"][0]
        self.assertTrue(first["complete"])
        self.assertFalse(first["incomplete"])
        self.assertTrue(first["exact_post"])
        self.assertFalse(first_post["text_complete"])
        self.assertTrue(first_post["text_truncated"])
        self.assertEqual(first_post["text_offset"], 0)
        self.assertEqual(len(first_post["text"]), 4000)
        self.assertEqual(first_post["text_next_offset"], 4000)
        self.assertEqual(first_post["text_total_chars"], len(full_text))

        second = await service.invoke("read_channel", reference=reference,
                                      text_offset=first_post["text_next_offset"])
        second_post = second["messages"][0]
        self.assertTrue(second["complete"])
        self.assertFalse(second["incomplete"])
        self.assertFalse(second_post["text_complete"])
        self.assertTrue(second_post["text_truncated"])
        self.assertEqual(second_post["text_offset"], 4000)
        self.assertEqual(second_post["text_next_offset"], None)
        self.assertEqual(first_post["text"] + second_post["text"], full_text)
        self.assertEqual(len(client.message_calls), 2)
        self.assertEqual([call[1] for call in client.message_calls], [{"ids": 81}, {"ids": 81}])

    async def test_short_exact_post_is_text_complete_and_offset_is_post_only(self):
        channel = public_channel()

        class Client:
            get_entity = AsyncMock(return_value=channel)

            async def get_messages(self, entity, **kwargs):
                if "ids" in kwargs:
                    return message(kwargs["ids"], "short body")
                return [message(81, "x" * 2500)]

        client = Client()
        service = Service(TelethonBackend(client), gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        exact = await service.invoke("read_channel", reference="https://t.me/niar42/81")
        post = exact["messages"][0]
        self.assertTrue(post["text_complete"])
        self.assertFalse(post["text_truncated"])
        self.assertIsNone(post["text_next_offset"])
        self.assertEqual(post["text"], "short body")

        history = await service.invoke("read_channel", reference="@niar42", limit=1)
        history_post = history["messages"][0]
        self.assertEqual(history_post["text"], "x" * 2000)
        self.assertTrue(history_post["text_truncated"])
        self.assertNotIn("text_complete", history_post)
        invalid = await service.invoke("read_channel", reference="@niar42", text_offset=1)
        self.assertEqual(invalid, {"error": "invalid_argument"})

    async def test_exact_post_text_offset_is_bounded_by_actual_text(self):
        channel = public_channel()

        class Client:
            get_entity = AsyncMock(return_value=channel)

            async def get_messages(self, entity, **kwargs):
                return message(kwargs["ids"], "short")

        service = Service(TelethonBackend(Client()), gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        result = await service.invoke("read_channel", reference="https://t.me/niar42/81",
                                      text_offset=6)
        self.assertEqual(result, {"error": "invalid_text_offset"})

    async def test_escaped_text_chunk_stays_inside_response_limit(self):
        channel = public_channel()

        class Client:
            get_entity = AsyncMock(return_value=channel)

            async def get_messages(self, entity, **kwargs):
                return message(kwargs["ids"], "\x00" * 5001)

        service = Service(TelethonBackend(Client()), gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        result = await service.invoke("read_channel", reference="https://t.me/niar42/81")
        post = result["messages"][0]
        self.assertEqual(len(post["text"]), 4000)
        self.assertEqual(post["text_next_offset"], 4000)
        self.assertFalse(post["text_complete"])

    async def test_gate_is_off_by_default_and_service_call_cannot_bypass_it(self):
        class Backend:
            calls = 0

            async def resolve_public_channel(self, username):
                self.calls += 1
                raise AssertionError("disabled gate must stop before resolution")

        backend = Backend()
        service = Service(backend, gate=RateGate(limit=1000))
        self.assertFalse(service.targeted_channel_reads_enabled)
        self.assertEqual(await service.invoke("read_channel", reference="niar42"),
                         {"error": "channel_reads_disabled"})
        with self.assertRaises(Denied) as caught:
            await service.read_channel("niar42")
        self.assertEqual(caught.exception.code, "channel_reads_disabled")
        self.assertEqual(backend.calls, 0)

    async def test_private_post_format_is_rejected_before_resolving_any_peer(self):
        client = SimpleNamespace(get_entity=AsyncMock())
        service = Service(TelethonBackend(client), gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        result = await service.invoke("read_channel", reference="https://t.me/c/2206439398/81")
        self.assertEqual(result, {"error": "invalid_channel_reference"})
        client.get_entity.assert_not_awaited()

    async def test_opt_in_public_read_does_not_enable_legacy_private_peer_route_or_writes(self):
        channel = public_channel()

        class Client:
            get_entity = AsyncMock(return_value=channel)

            async def get_messages(self, entity, **kwargs):
                if "ids" in kwargs:
                    return message(kwargs["ids"])
                return [message(81)]

        client = Client()
        backend = TelethonBackend(client)
        service = Service(backend, gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        target = get_peer_id(channel)
        result = await service.invoke("read_channel", reference="@niar42")
        self.assertEqual(len(result["messages"]), 1)
        history = await service.invoke("get_history", peer_id=target, limit=1)
        search = await service.invoke("search_messages", peer_id=target, query="post", limit=1)
        self.assertEqual(history, {"error": "peer_not_in_dialogs"})
        self.assertEqual(search, {"error": "peer_not_in_dialogs"})

    async def test_terminal_page_is_complete_and_wrong_post_id_is_not_returned(self):
        channel = public_channel()

        class Client:
            get_entity = AsyncMock(return_value=channel)

            async def get_messages(self, entity, **kwargs):
                if "ids" in kwargs:
                    return message(kwargs["ids"] - 1)
                return [message(80)]

        client = Client()
        service = Service(TelethonBackend(client), gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        page = await service.invoke("read_channel", reference="niar42", limit=2)
        self.assertEqual([item["message_id"] for item in page["messages"]], [80])
        self.assertTrue(page["complete"])
        self.assertFalse(page["incomplete"])
        self.assertIsNone(page["next_before_id"])
        missing = await service.invoke("read_channel", reference="https://t.me/niar42/81")
        self.assertEqual(missing, {"error": "message_missing"})

    async def test_non_channel_is_rejected_after_exact_username_resolution(self):
        for entity in (types.User(id=42),
                       public_channel(43, "publicgroup", broadcast=False, megagroup=True)):
            with self.subTest(entity=type(entity).__name__):
                client = SimpleNamespace(get_entity=AsyncMock(return_value=entity))
                backend = TelethonBackend(client)
                with self.assertRaises(Denied) as caught:
                    await backend.resolve_public_channel("niar42")
                self.assertEqual(caught.exception.code, "target_not_broadcast_channel")

    async def test_resolved_channel_username_must_match_the_requested_handle(self):
        client = SimpleNamespace(get_entity=AsyncMock(
            return_value=public_channel(44, "different")))
        backend = TelethonBackend(client)
        with self.assertRaises(Denied) as caught:
            await backend.resolve_public_channel("niar42")
        self.assertEqual(caught.exception.code, "peer_mismatch")

    async def test_channel_rate_limit_is_preserved_and_blocks_followup(self):
        class FloodWaitError(Exception):
            seconds = 9

        class Backend:
            def __init__(self):
                self.calls = 0

            async def resolve_public_channel(self, username):
                self.calls += 1
                raise FloodWaitError()

        now = [100.0]
        backend = Backend()
        service = Service(backend, gate=RateGate(clock=lambda: now[0]),
                          targeted_channel_reads_enabled=True)
        first = await service.invoke("read_channel", reference="niar42")
        second = await service.invoke("read_channel", reference="niar42")
        self.assertEqual(first, {"error": "telegram_rate_limited", "retry_after_seconds": 9})
        self.assertEqual(second, {"error": "telegram_rate_limited", "retry_after_seconds": 9})
        self.assertEqual(backend.calls, 1)
