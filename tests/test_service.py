import asyncio
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from telegram_assistant.security import Denied, Grant, Policy, Quotas, RateGate
from telegram_assistant.service import MAX_BYTES, SCOPES, Service, encode_response


def msg(i, **changes):
    return {"id": i, "text": f"caption {i}", "date": None, "sender_id": 42,
            "has_media": i % 2 == 0, **changes}


class Fake:
    def __init__(self):
        self.items = [msg(i) for i in range(12, 0, -1)]
        self.rows = [{"peer_id": i, "type": "user", "title": f"person {i}",
                      "archived": i % 2 == 0, "unread": 3} for i in range(1, 7)]
        self.rows += [{"peer_id": -99, "type": "group", "title": "group", "archived": True, "unread": 2},
                      {"peer_id": -100999, "type": "channel", "title": "channel", "archived": False, "unread": 0}]
        self.send = AsyncMock(return_value=99)
        self.read_receipt = AsyncMock()
        self.download_media = AsyncMock()
        self.history_calls = []
        self.dialog_calls = []
        self.peer_type = "user"
        self.human_user = True
        self.human_users = {}
        self.human_check_calls = []
        self.first_inbound = True
        self.first_contact_barrier = None
    def start_dialogs(self, archived):
        return {'rows': [dict(d) for d in self.rows if archived is None or d['archived'] == archived], 'at': 0}
    async def dialog_page(self, state, limit):
        self.dialog_calls.append(limit)
        rows = state['rows'][state['at']:state['at'] + limit]
        state['at'] += len(rows)
        return {'rows': rows, 'done': state['at'] == len(state['rows']), 'truncated': False}
    async def resolve(self, target):
        return target, self.peer_type
    async def is_human_user(self, target):
        self.human_check_calls.append(target)
        return self.human_users.get(target, self.human_user)
    async def verify_first_inbound(self, target, message_id):
        if self.first_contact_barrier is not None:
            await self.first_contact_barrier.wait()
        return self.first_inbound
    async def history(self, target, *, limit, before_id, query):
        self.history_calls.append((target, limit, before_id, query))
        return [m for m in self.items if (before_id is None or m["id"] < before_id)
                and (query is None or query in m["text"])][:limit]
    async def message(self, target, message_id):
        return next((m for m in self.items if m["id"] == message_id), None)
    async def around(self, target, message_id, radius):
        before = [m for m in self.items if m["id"] < message_id][:radius]
        after = sorted([m for m in self.items if m["id"] > message_id], key=lambda m:m["id"])[:radius]
        return before, after


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.context = SCOPES.set(frozenset({"telegram:read"}))
        self.fake = Fake()
        self.s = Service(self.fake, gate=RateGate(limit=1000))
    def tearDown(self):
        SCOPES.reset(self.context)
    async def call(self, operation, **kw):
        return await self.s.invoke(operation, **kw)
    async def test_history_cursor_survives_new_messages(self):
        a = await self.call("get_history", peer_id=42, limit=3)
        self.assertEqual([m["message_id"] for m in a["messages"]], [12, 11, 10])
        self.fake.items.insert(0, msg(13))
        b = await self.call("get_history", peer_id=42, limit=3, before_id=a["next_before_id"])
        self.assertEqual([m["message_id"] for m in b["messages"]], [9, 8, 7])
        self.assertEqual(self.fake.history_calls[-1][2], 10)
    async def test_search_pagination_and_empty(self):
        a = await self.call("search_messages", peer_id=42, query="caption", limit=5)
        b = await self.call("search_messages", peer_id=42, query="caption", limit=50, before_id=a["next_before_id"])
        self.assertEqual(len(b["messages"]), 7)
        self.assertIsNone(b["next_before_id"])
        self.assertEqual((await self.call("search_messages", peer_id=42, query="nothing"))["messages"], [])
    async def test_archive_snapshot_filters_and_new_dialog(self):
        a = await self.call("list_dialogs", archived=True, limit=2)
        self.fake.rows.insert(0, {"peer_id": 7, "type": "user", "title": "new", "archived": True, "unread": 1})
        b = await self.call("list_dialogs", archived=True, limit=2, cursor=a["next_cursor"])
        self.assertEqual([d["peer_id"] for d in a["dialogs"] + b["dialogs"]], [2,4,6,-99])
        self.assertIsNone(b["next_cursor"])
        all_rows = await self.call("list_dialogs", limit=50)
        self.assertNotIn("channel", [d["type"] for d in all_rows["dialogs"]])
    async def test_cursor_mismatch_and_expiry(self):
        now = [1000]
        self.s.clock = lambda: now[0]
        a = await self.call("list_dialogs", archived=True, limit=1)
        b = await self.call("list_dialogs", archived=False, cursor=a["next_cursor"])
        self.assertEqual(b["error"], "cursor_expired_or_mismatched")
        now[0] += 301
        b = await self.call("list_dialogs", archived=True, cursor=a["next_cursor"])
        self.assertIn("expired", b["error"])
    async def test_context_nearest_with_gaps(self):
        self.fake.items = [msg(i) for i in [100,70,12,8,3,1]]
        self.fake.items[2]["reply_to"] = 1
        a = await self.call("get_reply_context", peer_id=42, message_id=12, radius=1)
        self.assertEqual([m["message_id"] for m in a["messages"]], [8,12,70])
        self.assertEqual(a["replied_message"]["message_id"], 1)
    async def test_missing_and_cross_peer_reply(self):
        self.fake.items[0].update(reply_to=4, reply_peer_id=-99)
        a = await self.call("get_reply_context", peer_id=42, message_id=12)
        self.assertEqual(a["reply_state"], "cross_peer_reference_only")
        self.assertIsNone(a["replied_message"])
        self.fake.items[0].update(reply_peer_id=42, reply_to=99)
        self.assertEqual((await self.call("get_reply_context", peer_id=42, message_id=12))["reply_state"], "missing")
        self.assertEqual((await self.call("get_reply_context", peer_id=42, message_id=999))["error"], "message_missing")
    async def test_no_read_receipt_download_or_send(self):
        for op, kw in [("list_dialogs", {}), ("get_history", {"peer_id":42}),
                       ("search_messages", {"peer_id":42,"query":"caption"}),
                       ("get_reply_context", {"peer_id":42,"message_id":12})]:
            self.assertNotIn("error", await self.call(op, **kw))
        self.fake.read_receipt.assert_not_awaited()
        self.fake.download_media.assert_not_awaited()
        self.fake.send.assert_not_awaited()
    async def test_argument_bounds(self):
        for kw in [{"peer_id":42,"limit":0}, {"peer_id":42,"limit":51}, {"peer_id":True},
                   {"peer_id":"@someone"}, {"peer_id":0}, {"peer_id":42,"before_id":-1}]:
            self.assertIn("error", await self.call("get_history", **kw))
        for query in ["", " ", "x" *257, None]:
            self.assertEqual((await self.call("search_messages", peer_id=42, query=query))["error"], "invalid_query")
    async def test_unauthorized_and_hidden_mutations(self):
        SCOPES.set(frozenset())
        self.assertEqual((await self.call("get_history", peer_id=42))["error"], "unauthorized")
        SCOPES.set(frozenset({"telegram:read"}))
        for op in ["edit_message","delete_message","join","mark_read","set_policy"]:
            self.assertEqual((await self.call(op))["error"], "unknown_tool")
    async def test_default_deny_even_with_write_scope(self):
        SCOPES.set(frozenset({"telegram:read","telegram:send"}))
        a = await self.call("send_message", peer_id=42, text="test")
        self.assertEqual(a["error"], "send_denied")
        self.fake.send.assert_not_awaited()
    async def test_peer_mismatch_and_wrong_type(self):
        self.fake.resolve = AsyncMock(return_value=(43,"user"))
        self.assertEqual((await self.call("get_history",peer_id=42))["error"],"peer_mismatch")
        self.fake.resolve = AsyncMock(return_value=(42,"channel"))
        self.assertEqual((await self.call("get_history",peer_id=42))["error"],"peer_mismatch")
    async def test_response_bounds_and_continuation(self):
        self.fake.items = [msg(i, text="😀" *5000) for i in range(100,0,-1)]
        seen = []
        cursor = None
        for _ in range(30):
            a = await self.call("get_history",peer_id=42,limit=50,before_id=cursor)
            self.assertLessEqual(len(encode_response(a)), MAX_BYTES)
            self.assertTrue(all(m["text_truncated"] for m in a["messages"]))
            seen += [m["message_id"] for m in a["messages"]]
            cursor = a["next_before_id"]
            if cursor is None:
                break
        self.assertEqual(seen,list(range(100,0,-1)))
    async def test_flood_cooldown_no_repeat(self):
        class FloodWaitError(Exception):
            seconds=123
        self.fake.history = AsyncMock(side_effect=FloodWaitError("sensitive text"))
        a = await self.call("get_history",peer_id=42)
        self.assertEqual(a,{"error":"telegram_rate_limited","retry_after_seconds":123})
        b = await self.call("get_history",peer_id=42)
        self.assertEqual(b["error"],"telegram_rate_limited")
        self.fake.history.assert_awaited_once()
    async def test_exceptions_do_not_echo_secrets(self):
        secret = "session-and-message-secret"
        self.fake.history = AsyncMock(side_effect=RuntimeError(secret))
        a = await self.call("get_history",peer_id=42)
        self.assertEqual(a,{"error":"telegram_unavailable"})
        self.assertNotIn(secret,json.dumps(a))


class WriteTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/"quota.sqlite"
        self.q = Quotas(self.path)
        self.now = 100000
        self.g = Grant(42, 200000, 20, 1, 2)
        self.fake = Fake()
        self.s = Service(self.fake,Policy([self.g]),self.q,gate=RateGate(limit=1000),clock=lambda:self.now)
        self.context=SCOPES.set(frozenset({"telegram:read","telegram:send"}))
    def tearDown(self):
        SCOPES.reset(self.context)
        self.q.close()
        self.tmp.cleanup()
    async def test_scopes_expiry_target_and_utf16(self):
        SCOPES.set(frozenset({"telegram:read"}))
        self.assertEqual((await self.s.invoke("send_message",peer_id=42,text="x"))["error"],"send_scope_required")
        SCOPES.set(frozenset({"telegram:read","telegram:send"}))
        self.assertEqual((await self.s.invoke("send_message",peer_id=43,text="x"))["error"],"send_denied")
        self.assertEqual((await self.s.invoke("send_message",peer_id=42,text="😀"*11))["error"],"text_too_long")
        self.now=200000
        self.assertEqual((await self.s.invoke("send_message",peer_id=42,text="x"))["error"],"send_denied")
        self.fake.send.assert_not_awaited()
    async def test_concurrent_requests_and_restart_quota(self):
        a,b=await asyncio.gather(*(self.s.invoke("send_message",peer_id=42,text="test") for _ in range(2)))
        self.assertEqual(sum(x.get("sent",False) for x in [a,b]),1)
        self.assertEqual(self.fake.send.await_count,1)
        self.q.close()
        self.q=Quotas(self.path)
        self.s.quotas=self.q
        self.assertEqual((await self.s.invoke("send_message",peer_id=42,text="test"))["error"],"send_quota_exceeded")
        self.now+=61
        self.assertTrue((await self.s.invoke("send_message",peer_id=42,text="test"))["sent"])
        self.now+=61
        self.assertEqual((await self.s.invoke("send_message",peer_id=42,text="test"))["error"],"send_quota_exceeded")
    async def test_unknown_delivery_consumes_quota(self):
        self.fake.send.side_effect=TimeoutError("secret")
        self.assertEqual((await self.s.invoke("send_message",peer_id=42,text="test"))["error"],"delivery_unknown")
        self.assertEqual((await self.s.invoke("send_message",peer_id=42,text="test"))["error"],"send_quota_exceeded")
        self.fake.send.assert_awaited_once()
    async def test_missing_quote_denied_before_send(self):
        result=await self.s.invoke("send_message",peer_id=42,text="test",reply_to=999)
        self.assertEqual(result["error"],"reply_target_missing")
        self.fake.send.assert_not_awaited()


class SecurityTests(unittest.TestCase):
    def test_policy_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"policy.json"
            self.assertFalse(Policy.load(p).grants)
            p.write_text('{"version":1,"grants":[]}')
            p.chmod(0o600)
            self.assertFalse(Policy.load(p).grants)
            grant={"peer_id":42,"operation":"send_message","expires_at":200000,
                   "max_chars":100,"per_minute":1,"per_day":2}
            p.write_text(json.dumps({"version":1,"grants":[grant]}))
            self.assertIn(42,Policy.load(p).grants)
            p.chmod(0o644)
            self.assertFalse(Policy.load(p).grants)
            p.chmod(0o600)
            grant["operation"]="delete_message"
            p.write_text(json.dumps({"version":1,"grants":[grant]}))
            self.assertFalse(Policy.load(p).grants)
            link=Path(d)/"link.json"
            link.symlink_to(p)
            self.assertFalse(Policy.load(link).grants)
    def test_local_rate_limit(self):
        now=[0]
        g=RateGate(limit=2,clock=lambda:now[0])
        g.check();g.check()
        with self.assertRaises(Denied) as raised:g.check()
        self.assertEqual(raised.exception.retry_after,60)
        now[0]=60
        g.check()

    @staticmethod
    def v2(*, rules=(), grants=(), denies=(), global_per_minute=5, global_per_day=100):
        return Policy._parse({"version":2,"grants":list(grants),"rules":list(rules),
            "denies":list(denies),"global_limits":{"per_minute":global_per_minute,"per_day":global_per_day}})

    def test_v1_grants_remain_compatible_and_expiry_may_be_permanent(self):
        old={"version":1,"grants":[{"peer_id":42,"operation":"send_message","expires_at":200000,
                                        "max_chars":100,"per_minute":1,"per_day":2}]}
        policy=Policy._parse(old)
        self.assertEqual(policy.grants[42].expires_at,200000)
        self.assertEqual((policy.global_per_minute,policy.global_per_day),(1000,10000))
        old["grants"][0]["expires_at"]=None
        permanent=Policy._parse(old)
        self.assertIsNone(permanent.grants[42].expires_at)
        self.assertEqual(permanent.authorize(42,"x",frozenset({"telegram:send"}),10,
                                             peer_type="user",is_human=True).expires_at,None)

    def test_exact_user_grants_require_a_human_and_exact_groups_remain_allowed(self):
        grant={"peer_id":42,"operation":"send_message","expires_at":None,
               "max_chars":100,"per_minute":1,"per_day":20}
        policy=self.v2(grants=[grant])
        self.assertEqual(policy.authorize(42,"x",frozenset({"telegram:send"}),10,
                                          peer_type="user",is_human=True).peer_id,42)
        for peer_type,is_human in [("user",False),(None,False),("channel",False)]:
            with self.subTest(peer_type=peer_type,is_human=is_human):
                with self.assertRaises(Denied):
                    policy.authorize(42,"x",frozenset({"telegram:send"}),10,
                                     peer_type=peer_type,is_human=is_human)
        group=self.v2(grants=[{**grant,"peer_id":-99}])
        self.assertEqual(group.authorize(-99,"x",frozenset({"telegram:send"}),10,
                                         peer_type="group").peer_id,-99)

    def test_v2_selectors_deny_override_and_expiry(self):
        fields={"operation":"send_message","peer_ids":[],"expires_at":None,
                "max_chars":100,"per_minute":1,"per_day":20}
        rule={"id":"synthetic-all-dms","selector":"all_human_dms",**fields}
        p=self.v2(rules=[rule],denies=[{"peer_id":42,"expires_at":200}])
        with self.assertRaises(Denied):p.precheck(42,"x",frozenset({"telegram:send"}),100)
        self.assertEqual(p.authorize(43,"x",frozenset({"telegram:send"}),100,
                                     peer_type="user",is_human=True).per_day,20)
        self.assertEqual(p.authorize(42,"x",frozenset({"telegram:send"}),200,
                                     peer_type="user",is_human=True).per_day,20)
        with self.assertRaises(Denied):p.authorize(42,"x",frozenset({"telegram:send"}),100,
                                                   peer_type="user",is_human=False)

    def test_group_selectors_reject_channels_and_unknown_groups(self):
        fields={"operation":"send_message","peer_ids":[-99],"expires_at":None,
                "max_chars":100,"per_minute":1,"per_day":20}
        p=self.v2(rules=[{"id":"synthetic-group-set","selector":"group_ids",**fields},
                         {"id":"synthetic-all-groups","selector":"all_groups","peer_ids":[],
                          "operation":"send_message","expires_at":None,"max_chars":100,
                          "per_minute":1,"per_day":20}])
        self.assertEqual(p.authorize(-99,"x",frozenset({"telegram:send"}),100,
                                     peer_type="group").peer_id,-99)
        self.assertEqual(p.authorize(-100,"x",frozenset({"telegram:send"}),100,
                                     peer_type="group").peer_id,-100)
        with self.assertRaises(Denied):p.authorize(-99,"x",frozenset({"telegram:send"}),100,
                                                   peer_type="broadcast_channel")

    def test_bulk_rules_expire_at_boundary_and_require_send_scope(self):
        rule={"id":"synthetic-temporary-dms","selector":"all_human_dms","operation":"send_message",
              "peer_ids":[],"expires_at":200,"max_chars":100,"per_minute":1,"per_day":20}
        p=self.v2(rules=[rule])
        self.assertTrue(p.authorize(42,"x",frozenset({"telegram:send"}),199,
                                    peer_type="user",is_human=True).active(199))
        with self.assertRaises(Denied):p.precheck(42,"x",frozenset({"telegram:send"}),200)
        with self.assertRaises(Denied):p.precheck(42,"x",frozenset({"telegram:read"}),199)

    def test_global_send_quota_caps_multiple_recipients(self):
        with tempfile.TemporaryDirectory() as d:
            q=Quotas(Path(d)/"quota.sqlite")
            first=Grant(42,None,100,10,100,global_per_minute=5,global_per_day=1)
            second=Grant(43,None,100,10,100,global_per_minute=5,global_per_day=1)
            q.reserve(first,100)
            with self.assertRaises(Denied):q.reserve(second,101)
            q.close()

class ExtraWriteTests(unittest.IsolatedAsyncioTestCase):
    setUp = WriteTests.setUp
    tearDown = WriteTests.tearDown
    async def test_mismatch_refuses_before_quota_or_send(self):
        self.fake.resolve=AsyncMock(return_value=(43,"user"))
        result=await self.s.invoke("send_message",peer_id=42,text="test")
        self.assertEqual(result["error"],"peer_mismatch")
        self.fake.send.assert_not_awaited()
        self.assertEqual(self.q.db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0],0)

    async def test_exact_grant_checks_bot_and_self_before_send(self):
        grants=[{"peer_id":peer,"operation":"send_message","expires_at":None,
                 "max_chars":100,"per_minute":1,"per_day":20} for peer in (42,43)]
        self.s.policy=SecurityTests.v2(grants=grants)
        self.fake.human_users={42:False,43:False}
        for peer,kind in ((42,"bot"),(43,"self")):
            with self.subTest(kind=kind):
                result=await self.s.invoke("send_message",peer_id=peer,text="operator-approved text")
                self.assertEqual(result["error"],"peer_not_human")
                self.assertIn(peer,self.fake.human_check_calls)
                self.fake.send.assert_not_awaited()

    async def test_exact_group_grant_stays_limited_to_its_peer(self):
        self.s.policy=SecurityTests.v2(grants=[{"peer_id":-99,"operation":"send_message",
            "expires_at":None,"max_chars":100,"per_minute":1,"per_day":20}])
        self.fake.peer_type="group"
        result=await self.s.invoke("send_message",peer_id=-99,text="operator-approved text")
        self.assertTrue(result["sent"])
        self.fake.send.reset_mock()
        denied=await self.s.invoke("send_message",peer_id=-98,text="operator-approved text")
        self.assertEqual(denied["error"],"send_denied")
        self.fake.send.assert_not_awaited()
    async def test_expiry_rechecked_after_resolution(self):
        async def resolve(target):
            self.now=200000
            return target,"user"
        self.fake.resolve=resolve
        result=await self.s.invoke("send_message",peer_id=42,text="test")
        self.assertEqual(result["error"],"send_denied")
        self.fake.send.assert_not_awaited()

    async def test_bulk_human_rule_excludes_bots_and_groups(self):
        self.s.policy=SecurityTests.v2(rules=[{"id":"synthetic-human-rule","operation":"send_message",
            "selector":"all_human_dms","peer_ids":[],"expires_at":None,"max_chars":100,
            "per_minute":1,"per_day":20}])
        self.assertTrue((await self.s.invoke("send_message",peer_id=42,text="approved by user"))["sent"])
        self.fake.send.reset_mock()
        self.fake.human_user=False
        self.assertEqual((await self.s.invoke("send_message",peer_id=43,text="approved by user"))["error"],"peer_not_human")
        self.assertFalse(self.fake.send.await_count)
        self.fake.human_user=True
        self.fake.peer_type="group"
        self.assertEqual((await self.s.invoke("send_message",peer_id=44,text="approved by user"))["error"],"send_denied")
        self.assertFalse(self.fake.send.await_count)

    async def test_selected_group_rule_rejects_other_peer_and_channel(self):
        self.s.policy=SecurityTests.v2(rules=[{"id":"synthetic-selected-groups","operation":"send_message",
            "selector":"group_ids","peer_ids":[-99],"expires_at":None,"max_chars":100,
            "per_minute":1,"per_day":20}])
        self.fake.peer_type="group"
        self.assertTrue((await self.s.invoke("send_message",peer_id=-99,text="user instruction"))["sent"])
        self.fake.send.reset_mock()
        self.assertEqual((await self.s.invoke("send_message",peer_id=-98,text="user instruction"))["error"],"send_denied")
        self.assertFalse(self.fake.send.await_count)
        self.fake.peer_type="channel"
        self.assertEqual((await self.s.invoke("send_message",peer_id=-99,text="user instruction"))["error"],"peer_mismatch")
        self.assertFalse(self.fake.send.await_count)

    async def test_first_contact_requires_verified_inbound_message_and_deduplicates(self):
        self.s.policy=SecurityTests.v2(rules=[{"id":"synthetic-first-contact","operation":"send_message",
            "selector":"first_contact","peer_ids":[],"expires_at":None,"max_chars":100,
            "per_minute":1,"per_day":20}])
        self.assertEqual((await self.s.invoke("send_message",peer_id=42,text="user instruction"))["error"],
                         "first_contact_message_required")
        self.assertEqual((await self.s.invoke("send_message",peer_id=42,text="user instruction",reply_to=9,
                    first_contact_message_id=10))["error"],"invalid_first_contact_reference")
        self.fake.first_inbound=False
        self.assertEqual((await self.s.invoke("send_message",peer_id=42,text="user instruction",reply_to=10,
                    first_contact_message_id=10))["error"],"first_contact_unverified")
        self.fake.send.assert_not_awaited()
        self.fake.first_inbound=True
        result=await self.s.invoke("send_message",peer_id=42,text="user instruction",reply_to=10,
                                   first_contact_message_id=10)
        self.assertTrue(result["sent"])
        duplicate=await self.s.invoke("send_message",peer_id=42,text="user instruction",reply_to=10,
                                      first_contact_message_id=10)
        self.assertEqual(duplicate["error"],"first_contact_already_handled")
        self.assertEqual(self.fake.send.await_count,1)
        self.assertEqual(self.q.db.execute("SELECT state FROM first_contact_attempts").fetchone()[0],"sent")

    async def test_first_contact_unknown_delivery_is_terminal(self):
        self.s.policy=SecurityTests.v2(rules=[{"id":"synthetic-first-contact","operation":"send_message",
            "selector":"first_contact","peer_ids":[],"expires_at":None,"max_chars":100,
            "per_minute":1,"per_day":20}])
        self.fake.send.side_effect=TimeoutError("synthetic timeout")
        result=await self.s.invoke("send_message",peer_id=42,text="user instruction",reply_to=10,
                                   first_contact_message_id=10)
        self.assertEqual(result["error"],"delivery_unknown")
        replay=await self.s.invoke("send_message",peer_id=42,text="user instruction",reply_to=10,
                                   first_contact_message_id=10)
        self.assertEqual(replay["error"],"first_contact_already_handled")
        self.assertEqual(self.fake.send.await_count,1)
        self.assertEqual(self.q.db.execute("SELECT state FROM first_contact_attempts").fetchone()[0],"unknown")

    async def test_first_contact_history_error_fails_closed(self):
        self.s.policy=SecurityTests.v2(rules=[{"id":"synthetic-first-contact","operation":"send_message",
            "selector":"first_contact","peer_ids":[],"expires_at":None,"max_chars":100,
            "per_minute":1,"per_day":20}])
        self.fake.verify_first_inbound=AsyncMock(side_effect=RuntimeError("synthetic history failure"))
        result=await self.s.invoke("send_message",peer_id=42,text="user instruction",reply_to=10,
                                   first_contact_message_id=10)
        self.assertEqual(result["error"],"first_contact_unavailable")
        self.fake.send.assert_not_awaited()
        self.assertEqual(self.q.db.execute("SELECT COUNT(*) FROM first_contact_attempts").fetchone()[0],0)

    async def test_first_contact_race_reserves_once_across_connections(self):
        self.s.policy=SecurityTests.v2(rules=[{"id":"synthetic-first-contact","operation":"send_message",
            "selector":"first_contact","peer_ids":[],"expires_at":None,"max_chars":100,
            "per_minute":1,"per_day":20}])
        barrier=asyncio.Barrier(2)
        self.fake.first_contact_barrier=barrier
        other_q=Quotas(self.path)
        other=Service(self.fake,self.s.policy,other_q,gate=RateGate(limit=1000),clock=lambda:self.now)
        args=dict(peer_id=42,text="user instruction",reply_to=10,first_contact_message_id=10)
        try:
            results=await asyncio.gather(self.s.invoke("send_message",**args),other.invoke("send_message",**args))
            self.assertEqual(sum(bool(x.get("sent")) for x in results),1)
            self.assertEqual(self.fake.send.await_count,1)
            errors=[x.get("error") for x in results if x.get("error")]
            self.assertEqual(errors,["first_contact_already_handled"])
        finally:
            other_q.close()
