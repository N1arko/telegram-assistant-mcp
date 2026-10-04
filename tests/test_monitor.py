import tempfile
import unittest
from pathlib import Path

from telegram_assistant.security import Quotas, RateGate
from telegram_assistant.service import MAX_BYTES, SCOPES, Service, wire_size


def message(message_id, *, out=False, peer_id=42):
    return {"id": message_id, "text": f"message {message_id}", "date": None,
            "sender_id": peer_id, "has_media": False, "out": out}


class MonitorBackend:
    def __init__(self, rows, messages=None, *, truncated=False):
        self.rows = [dict(row) for row in rows]
        self.messages = messages or {}
        self.truncated = truncated
        self.catalog_calls = []
        self.message_calls = []
        self.message_failure = None
        self.types = {row["peer_id"]: row["type"] for row in self.rows}

    def start_dialogs(self, archived):
        return {"rows": [dict(row) for row in self.rows
                         if archived is None or row["archived"] == archived], "at": 0}

    async def dialog_page(self, state, limit):
        self.catalog_calls.append(limit)
        rows = state["rows"][state["at"]:state["at"] + limit]
        state["at"] += len(rows)
        done = state["at"] == len(state["rows"])
        return {"rows": rows, "done": done or self.truncated, "truncated": self.truncated}

    async def resolve(self, target):
        return target, self.types[target]

    async def new_messages(self, target, *, after_id, through_id, limit):
        self.message_calls.append((target, after_id, through_id, limit))
        if self.message_failure is not None:
            failure, self.message_failure = self.message_failure, None
            raise failure
        rows = [row for row in self.messages.get(target, ())
                if after_id < row["id"] <= through_id]
        return sorted(rows, key=lambda row: row["id"])[:limit + 1]


class MonitorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.context = SCOPES.set(frozenset({"telegram:read"}))
        self.temp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp.name) / "runtime" / "quotas.sqlite"

    def tearDown(self):
        SCOPES.reset(self.context)
        self.temp.cleanup()

    def service(self, backend, *, quotas=None, clock=None):
        quotas = quotas or Quotas(self.db_path)
        options = {"clock": clock} if clock is not None else {}
        return Service(backend, quotas=quotas, gate=RateGate(limit=1000), **options), quotas

    @staticmethod
    def row(peer, latest, read_max, kind="user"):
        return {"peer_id": peer, "type": kind, "title": str(peer), "archived": True,
                "unread": max(0, latest - read_max), "latest_message_id": latest,
                "latest_message_date": None, "read_inbox_max_id": read_max}

    async def test_first_scan_includes_recent_read_dm_window_and_skips_old_group_history(self):
        backend = MonitorBackend(
            [self.row(42, 12, 10), self.row(-90, 200, 198, "group")],
            {42: [message(i) for i in range(9, 13)],
             -90: [message(i, peer_id=-90) for i in (199, 200)]})
        service, quotas = self.service(backend)
        try:
            result = await service.invoke("scan_updates", limit=3)
            self.assertEqual([m["message_id"] for m in result["messages"]], [9, 10, 11])
            self.assertEqual(backend.message_calls, [(42, 0, 12, 3)])
            self.assertEqual(result["initial_window_messages"], 20)
            self.assertFalse(result["initial_history_incomplete"])
            self.assertEqual(quotas.next_monitor_pending()["peer_id"], 42)
            checkpoint = quotas.db.execute(
                "SELECT message_id,peer_type FROM monitor_checkpoints WHERE peer=-90").fetchone()
            self.assertEqual(checkpoint, (200, "group"))
            self.assertFalse(result["coverage_complete"])
            backend.messages[-90].append(message(201, peer_id=-90))
            backend.rows[1]["latest_message_id"] = 201
            dm_tail = await service.invoke("scan_updates", limit=3, cursor=result["next_cursor"])
            self.assertEqual([m["message_id"] for m in dm_tail["messages"]], [12])
            group_page = await service.invoke("scan_updates", limit=3, cursor=dm_tail["next_cursor"])
            self.assertEqual([(m["peer_id"],m["message_id"]) for m in group_page["messages"]],
                             [(-90,201)])
            await service.invoke("scan_updates", limit=3, cursor=group_page["next_cursor"])
            checkpoint = quotas.db.execute(
                "SELECT message_id,peer_type FROM monitor_checkpoints WHERE peer=-90").fetchone()
            self.assertEqual(checkpoint, (201, "group"))
        finally:
            quotas.close()

    async def test_continuation_is_oldest_first_and_catches_new_message_during_pagination(self):
        backend = MonitorBackend([self.row(42, 4, 0)], {42: [
            message(1), message(2, out=True), message(3), message(4)]})
        service, quotas = self.service(backend)
        try:
            first = await service.invoke("scan_updates", limit=2)
            self.assertEqual([m["message_id"] for m in first["messages"]], [1, 2])
            self.assertTrue(first["messages"][1]["out"])
            backend.messages[42].append(message(5, out=True))
            backend.rows[0]["latest_message_id"] = 5

            second = await service.invoke("scan_updates", limit=2, cursor=first["next_cursor"])
            self.assertEqual([m["message_id"] for m in second["messages"]], [3, 4])
            third = await service.invoke("scan_updates", limit=2, cursor=second["next_cursor"])
            self.assertEqual([m["message_id"] for m in third["messages"]], [5])
            self.assertTrue(third["messages"][0]["out"])
            self.assertEqual([call[:3] for call in backend.message_calls],
                             [(42, 0, 4), (42, 2, 4), (42, 4, 5)])
        finally:
            quotas.close()

    async def test_busy_peer_is_requeued_behind_other_dialogs(self):
        backend = MonitorBackend([self.row(42, 3, 0), self.row(43, 3, 0)], {
            42: [message(i) for i in range(1, 4)],
            43: [message(i, peer_id=43) for i in range(1, 4)]})
        service, quotas = self.service(backend)
        try:
            first = await service.invoke("scan_updates", limit=1)
            self.assertEqual(first["messages"][0]["peer_id"], 42)
            second = await service.invoke("scan_updates", limit=1, cursor=first["next_cursor"])
            self.assertEqual(second["messages"][0]["peer_id"], 43)
            self.assertEqual(second["messages"][0]["message_id"], 1)
            # First call discovers both peers. During queue drain the second
            # call spends one history RPC and no additional catalogue RPC.
            self.assertEqual(backend.catalog_calls, [50])
            self.assertEqual(len(backend.message_calls), 2)
        finally:
            quotas.close()

    async def test_large_direct_chat_bootstrap_is_bounded_and_checkpoint_waits_for_ack(self):
        backend = MonitorBackend([self.row(42, 100, 100)], {
            42: [message(i) for i in range(81, 101)]})
        backend.message_failure = RuntimeError("synthetic fetch failure")
        service, quotas = self.service(backend)
        try:
            failed = await service.invoke("scan_updates", limit=10)
            self.assertEqual(failed["error"], "telegram_unavailable")
            self.assertEqual(quotas.db.execute(
                "SELECT message_id FROM monitor_checkpoints WHERE peer=42").fetchone(), (80,))
            self.assertEqual(quotas.monitor_initial_window_limited_count(), 1)

            first = await service.invoke("scan_updates", limit=10)
            ids = [row["message_id"] for row in first["messages"]]
            self.assertEqual(ids, list(range(81, 91)))
            self.assertTrue(first["initial_history_incomplete"])
            self.assertEqual(first["initial_window_limited_dialogs"], 1)
            # Returning the page and replaying it do not advance the durable
            # checkpoint. Only presenting its output cursor acknowledges it.
            self.assertEqual(quotas.db.execute(
                "SELECT message_id FROM monitor_checkpoints WHERE peer=42").fetchone(), (80,))
            replay = await service.invoke("scan_updates", limit=10)
            self.assertEqual([row["message_id"] for row in replay["messages"]], ids)
            self.assertEqual(quotas.db.execute(
                "SELECT message_id FROM monitor_checkpoints WHERE peer=42").fetchone(), (80,))
            second = await service.invoke(
                "scan_updates", limit=10, cursor=first["next_cursor"])
            self.assertEqual([row["message_id"] for row in second["messages"]], list(range(91, 101)))
            self.assertEqual(quotas.db.execute(
                "SELECT message_id FROM monitor_checkpoints WHERE peer=42").fetchone(), (90,))
        finally:
            quotas.close()
        self.assertNotIn(b"message 81", self.db_path.read_bytes())

    async def test_empty_dialog_is_not_checkpointed_before_it_becomes_active(self):
        backend = MonitorBackend([self.row(42, 0, 0)], {})
        service, quotas = self.service(backend)
        try:
            first = await service.invoke("scan_updates")
            self.assertIsNone(quotas.db.execute(
                "SELECT 1 FROM monitor_checkpoints WHERE peer=42").fetchone())
            backend.rows[0]["latest_message_id"] = 100
            backend.messages[42] = [message(i) for i in range(81, 101)]
            second = await service.invoke("scan_updates", cursor=first["next_cursor"])
            self.assertEqual([row["message_id"] for row in second["messages"]], list(range(81, 86)))
            self.assertTrue(second["initial_history_incomplete"])
            self.assertEqual(quotas.db.execute(
                "SELECT message_id FROM monitor_checkpoints WHERE peer=42").fetchone(), (80,))
        finally:
            quotas.close()

    async def test_empty_fetched_range_advances_only_after_empty_page_cursor_is_acknowledged(self):
        backend = MonitorBackend([self.row(42, 5, 5)], {42: []})
        service, quotas = self.service(backend)
        try:
            empty = await service.invoke("scan_updates", limit=5)
            self.assertEqual(empty["messages"], [])
            self.assertEqual(quotas.db.execute(
                "SELECT message_id FROM monitor_checkpoints WHERE peer=42").fetchone(), (0,))
            next_page = await service.invoke(
                "scan_updates", limit=5, cursor=empty["next_cursor"])
            self.assertEqual(next_page["messages"], [])
            self.assertEqual(quotas.db.execute(
                "SELECT message_id FROM monitor_checkpoints WHERE peer=42").fetchone(), (5,))
        finally:
            quotas.close()

    async def test_unacked_page_replays_across_restart_then_expired_catalog_restarts(self):
        rows = [self.row(42, 2, 0)] + [self.row(i, 0, 0) for i in range(100, 150)]
        messages = {42: [message(1), message(2)]}
        backend1 = MonitorBackend(rows, messages)
        service1, quotas1 = self.service(backend1)
        first = await service1.invoke("scan_updates", limit=1)
        self.assertEqual([m["message_id"] for m in first["messages"]], [1])
        quotas1.close()

        backend2 = MonitorBackend(rows, messages)
        service2, quotas2 = self.service(backend2)
        try:
            replay = await service2.invoke("scan_updates", limit=1)
            self.assertEqual([m["message_id"] for m in replay["messages"]], [1])
            self.assertEqual(backend2.catalog_calls, [])
            next_page = await service2.invoke(
                "scan_updates", limit=1, cursor=first["next_cursor"])
            self.assertEqual([m["message_id"] for m in next_page["messages"]], [2])
            self.assertTrue(next_page["coverage_restarted"])
            self.assertFalse(next_page["coverage_complete"])
            self.assertEqual(backend2.catalog_calls, [50])
        finally:
            quotas2.close()

    async def test_truncated_catalog_is_explicitly_incomplete(self):
        backend = MonitorBackend([self.row(42, 0, 0)], truncated=True)
        service, quotas = self.service(backend)
        try:
            result = await service.invoke("scan_updates")
            self.assertTrue(result["scan_truncated"])
            self.assertFalse(result["catalogue_complete"])
            self.assertFalse(result["coverage_complete"])
        finally:
            quotas.close()

    async def test_new_dialog_is_found_on_next_complete_sweep(self):
        backend = MonitorBackend([self.row(42, 0, 0)], {})
        service, quotas = self.service(backend)
        try:
            first = await service.invoke("scan_updates")
            backend.rows.append(self.row(43, 8, 7))
            backend.types[43] = "user"
            backend.messages[43] = [message(7, peer_id=43), message(8, peer_id=43)]
            second = await service.invoke("scan_updates", cursor=first["next_cursor"])
            self.assertEqual([(m["peer_id"],m["message_id"]) for m in second["messages"]],
                             [(43, 7), (43, 8)])
            self.assertEqual(backend.catalog_calls,[50,50])
        finally:
            quotas.close()

    async def test_large_json_escaped_page_is_trimmed_without_skipping_tail(self):
        backend = MonitorBackend([self.row(42, 10, 0)], {
            42: [{**message(i), "text": "\\" * 2000} for i in range(1, 11)]})
        service, quotas = self.service(backend)
        try:
            first = await service.invoke("scan_updates", limit=10)
            self.assertLessEqual(wire_size(first), MAX_BYTES)
            self.assertTrue(len(first["messages"]) < 10)
            self.assertLess(first["messages"][-1]["message_id"], 10)
            replay = await service.invoke("scan_updates", limit=10)
            self.assertEqual([m["message_id"] for m in replay["messages"]],
                             [m["message_id"] for m in first["messages"]])
            next_page = await service.invoke("scan_updates", limit=10, cursor=first["next_cursor"])
            self.assertEqual(next_page["messages"][0]["message_id"],
                             first["messages"][-1]["message_id"] + 1)
            self.assertEqual(next_page["messages"][-1]["message_id"], 10)
        finally:
            quotas.close()

    async def test_five_minute_catalog_cursor_expiry_keeps_watermarks_and_reports_restart(self):
        rows = [self.row(42, 2, 0)] + [self.row(i, 0, 0) for i in range(100, 150)]
        backend = MonitorBackend(rows, {42: [message(1), message(2)]})
        now = [1000]
        service, quotas = self.service(backend, clock=lambda: now[0])
        try:
            first = await service.invoke("scan_updates", limit=1)
            now[0] += 301
            continued = await service.invoke("scan_updates", limit=1, cursor=first["next_cursor"])
            self.assertEqual([m["message_id"] for m in continued["messages"]],[2])
            self.assertTrue(continued["coverage_restarted"])
            self.assertEqual(backend.catalog_calls,[50,50])
        finally:
            quotas.close()

    async def test_flood_wait_is_reported_without_retry_loop_and_queue_is_kept(self):
        class FloodWaitError(Exception):
            seconds = 4

        backend = MonitorBackend([self.row(42, 1, 0)], {42: [message(1)]})
        backend.message_failure = FloodWaitError("private telegram payload")
        now = [100]
        service, quotas = self.service(backend)
        service.gate = RateGate(clock=lambda: now[0], limit=1000)
        try:
            first = await service.invoke("scan_updates", limit=1)
            self.assertEqual(first["error"], "telegram_rate_limited")
            self.assertEqual(first["retry_after_seconds"], 4)
            self.assertNotIn("private telegram payload", repr(first))
            self.assertEqual(len(backend.message_calls), 1)
            self.assertEqual(quotas.monitor_pending_count(), 1)
            blocked = await service.invoke("scan_updates", limit=1)
            self.assertEqual(blocked["retry_after_seconds"], 4)
            self.assertEqual(len(backend.message_calls), 1)
            now[0] += 4
            result = await service.invoke("scan_updates", limit=1)
            self.assertEqual([m["message_id"] for m in result["messages"]], [1])
            self.assertEqual(len(backend.message_calls), 2)
        finally:
            quotas.close()

    async def test_cursor_is_required_to_ack_and_read_scope_is_enforced(self):
        backend = MonitorBackend([self.row(42, 0, 0)])
        service, quotas = self.service(backend)
        try:
            first = await service.invoke("scan_updates")
            invalid = await service.invoke("scan_updates", cursor="not-the-current-cursor")
            self.assertEqual(invalid["error"], "invalid_cursor")
            self.assertEqual(service.quotas.monitor_pending_count(), 0)
            context = SCOPES.set(frozenset())
            try:
                denied = await service.invoke("scan_updates")
            finally:
                SCOPES.reset(context)
            self.assertEqual(denied["error"], "unauthorized")
            self.assertIsNotNone(first["next_cursor"])
        finally:
            quotas.close()


if __name__ == "__main__":
    unittest.main()
