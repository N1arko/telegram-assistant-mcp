import unittest
from types import SimpleNamespace

from telegram_assistant.security import Denied, RateGate
from telegram_assistant.service import SCOPES, Service


CHANNEL = {
    "peer_id": -1002206439398,
    "type": "broadcast_channel",
    "username": "niar42",
    "title": "Niar",
}


class PublicChannelListTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scope = SCOPES.set(frozenset({"telegram:read"}))

    async def asyncTearDown(self):
        SCOPES.reset(self.scope)

    async def test_gate_is_off_by_default_and_blocks_the_service_path(self):
        backend = SimpleNamespace(
            start_public_channel_listing=lambda: self.fail("gate must stop before backend"))
        service = Service(backend, gate=RateGate(limit=1000))
        self.assertEqual(await service.invoke("list_public_channels"),
                         {"error": "channel_reads_disabled"})
        with self.assertRaises(Denied) as caught:
            await service.list_public_channels()
        self.assertEqual(caught.exception.code, "channel_reads_disabled")

    async def test_returns_only_public_metadata_and_never_fetches_history(self):
        class Backend:
            def __init__(self):
                self.page_calls = 0
                self.state = object()

            def start_public_channel_listing(self):
                return self.state

            async def public_channel_page(self, state, limit):
                self.page_calls += 1
                self.assert_state = state is self.state
                return {
                    "rows": [
                        {**CHANNEL, "unread": 123, "latest_message": "secret post"},
                        {"peer_id": -1002206439399, "type": "group",
                         "username": "groupname", "title": "private group"},
                        {"peer_id": -1002206440000, "type": "broadcast_channel",
                         "username": "bad/name", "title": "invalid handle"},
                    ],
                    "done": True,
                    "truncated": False,
                }

        backend = Backend()
        service = Service(backend, gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        result = await service.invoke("list_public_channels", limit=20)
        self.assertEqual(result["channels"], [{
            "peer_id": CHANNEL["peer_id"], "username": "niar42", "title": "Niar",
            "title_truncated": False, "public_url": "https://t.me/niar42",
        }])
        self.assertEqual(set(result), {
            "channels", "next_cursor", "complete", "incomplete", "truncated",
            "untrusted_content",
        })
        self.assertTrue(result["complete"])
        self.assertFalse(result["incomplete"])
        self.assertFalse(result["truncated"])
        self.assertNotIn("secret post", repr(result))
        self.assertNotIn("unread", repr(result))
        self.assertEqual(backend.page_calls, 1)
        self.assertTrue(backend.assert_state)

    async def test_page_limit_is_positive_and_capped_at_fifty(self):
        class Backend:
            calls = 0

            def start_public_channel_listing(self):
                self.calls += 1
                return object()

        backend = Backend()
        service = Service(backend, gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        for limit in (0, 51):
            self.assertEqual(await service.invoke("list_public_channels", limit=limit),
                             {"error": "invalid_argument"})
        self.assertEqual(backend.calls, 0)

    async def test_bounded_pages_replay_stably_and_mark_final_page_complete(self):
        class Backend:
            def __init__(self):
                self.pages = [
                    {"rows": [{**CHANNEL, "title": "first"}], "done": False,
                     "truncated": False},
                    {"rows": [{**CHANNEL, "peer_id": -1002206439399,
                               "username": "second", "title": "second"}],
                     "done": True, "truncated": False},
                ]
                self.calls = 0

            def start_public_channel_listing(self):
                return object()

            async def public_channel_page(self, state, limit):
                self.calls += 1
                self.last_limit = limit
                return self.pages.pop(0)

        backend = Backend()
        service = Service(backend, gate=RateGate(limit=1000),
                          targeted_channel_reads_enabled=True)
        first = await service.invoke("list_public_channels", limit=1)
        self.assertEqual(len(first["channels"]), 1)
        self.assertFalse(first["complete"])
        self.assertTrue(first["incomplete"])
        self.assertIsNotNone(first["next_cursor"])
        self.assertEqual(backend.last_limit, 1)

        cursor = first["next_cursor"]
        second = await service.invoke("list_public_channels", limit=1, cursor=cursor)
        replay = await service.invoke("list_public_channels", limit=1, cursor=cursor)
        self.assertEqual(second, replay)
        self.assertEqual([row["username"] for row in second["channels"]], ["second"])
        self.assertTrue(second["complete"])
        self.assertFalse(second["incomplete"])
        self.assertIsNone(second["next_cursor"])
        self.assertEqual(backend.calls, 2)

    async def test_flood_wait_returns_retry_after_and_preserves_the_listing_cursor(self):
        class FloodWaitError(Exception):
            seconds = 7

        class Backend:
            def __init__(self):
                self.calls = 0

            def start_public_channel_listing(self):
                return object()

            async def public_channel_page(self, state, limit):
                self.calls += 1
                if self.calls == 1:
                    raise FloodWaitError()
                return {"rows": [CHANNEL], "done": True, "truncated": False}

        now = [100.0]
        backend = Backend()
        service = Service(backend, gate=RateGate(clock=lambda: now[0]),
                          targeted_channel_reads_enabled=True)
        limited = await service.invoke("list_public_channels", limit=1)
        self.assertEqual(limited, {"error": "telegram_rate_limited",
                                   "retry_after_seconds": 7})
        still_limited = await service.invoke("list_public_channels", limit=1)
        self.assertEqual(still_limited, limited)
        self.assertEqual(backend.calls, 1)

        now[0] += 8
        result = await service.invoke("list_public_channels", limit=1)
        self.assertEqual([row["username"] for row in result["channels"]], ["niar42"])
        self.assertTrue(result["complete"])
        self.assertEqual(backend.calls, 2)

