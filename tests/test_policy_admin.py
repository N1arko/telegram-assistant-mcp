import json
import contextlib
import io
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from telegram_assistant.policy_admin import main, update_policy
from telegram_assistant.security import Denied, Policy


class PolicyAdminTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.path = self.root / "operator-policy.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_add_permanent_and_temporary_exact_grants_then_revoke(self):
        update_policy(self.path, "grant_peer", peer_ids=[42], expires_at=None)
        update_policy(self.path, "grant_peer", peer_ids=[43], expires_at=200000)
        policy = Policy.load_strict(self.path)
        self.assertIsNone(policy.grants[42].expires_at)
        self.assertEqual(policy.grants[43].expires_at, 200000)
        update_policy(self.path, "revoke_peer", peer_ids=[42])
        self.assertNotIn(42, Policy.load_strict(self.path).grants)
        self.assertIn(43, Policy.load_strict(self.path).grants)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_v1_edit_migrates_to_safe_v2_global_defaults(self):
        self.path.write_text(json.dumps({"version":1,"grants":[{"peer_id":42,"operation":"send_message",
            "expires_at":None,"max_chars":4096,"per_minute":1,"per_day":20}]}))
        self.path.chmod(0o600)
        self.assertEqual((Policy.load_strict(self.path).global_per_minute,
                          Policy.load_strict(self.path).global_per_day),(1000,10000))
        update_policy(self.path,"grant_rule",selector="all_human_dms")
        upgraded=Policy.load_strict(self.path)
        self.assertIn(42,upgraded.grants)
        self.assertEqual((upgraded.global_per_minute,upgraded.global_per_day),(5,100))

    def test_add_bulk_selector_deny_precedence_and_revoke(self):
        rule_id = update_policy(self.path, "grant_rule", selector="all_human_dms")
        update_policy(self.path, "deny_peer", peer_ids=[42])
        policy = Policy.load_strict(self.path)
        with self.assertRaises(Denied):
            policy.precheck(42, "text", frozenset({"telegram:send"}), 100)
        self.assertTrue(policy.precheck(43, "text", frozenset({"telegram:send"}), 100))
        update_policy(self.path, "revoke_rule", rule_id=rule_id)
        self.assertFalse(Policy.load_strict(self.path).rules)
        update_policy(self.path, "allow_peer", peer_ids=[42])
        self.assertFalse(Policy.load_strict(self.path).denies)

    def test_group_set_and_all_groups_are_disabled_until_operator_adds_them(self):
        self.assertFalse(Policy.load(self.path).rules)
        group_rule = update_policy(self.path, "grant_rule", selector="group_ids", peer_ids=[-99, -100123])
        all_rule = update_policy(self.path, "grant_rule", selector="all_groups")
        rules = {rule.rule_id: rule for rule in Policy.load_strict(self.path).rules}
        self.assertEqual(rules[group_rule].peer_ids, (-99, -100123))
        self.assertEqual(rules[all_rule].selector, "all_groups")
        update_policy(self.path, "revoke_peer", peer_ids=[-99])
        remaining = {rule.rule_id: rule for rule in Policy.load_strict(self.path).rules}
        self.assertEqual(remaining[group_rule].peer_ids, (-100123,))
        self.assertIn(all_rule, remaining)

    def test_atomic_concurrent_updates_preserve_both_changes(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(update_policy, self.path, "grant_peer", peer_ids=[peer])
                       for peer in (42, 43)]
            for future in futures:
                future.result()
        self.assertEqual(set(Policy.load_strict(self.path).grants), {42, 43})

    def test_corrupt_policy_is_never_overwritten(self):
        self.path.write_text("not-json")
        self.path.chmod(0o600)
        before = self.path.read_bytes()
        with self.assertRaises((ValueError, json.JSONDecodeError)):
            update_policy(self.path, "grant_peer", peer_ids=[42])
        self.assertEqual(self.path.read_bytes(), before)

    def test_global_quotas_are_configurable_and_fail_closed(self):
        update_policy(self.path, "set_limits", per_minute=3, per_day=80)
        policy=Policy.load_strict(self.path)
        self.assertEqual((policy.global_per_minute,policy.global_per_day),(3,80))
        with self.assertRaises(Denied):
            update_policy(self.path, "set_limits", per_minute=0, per_day=80)

    def test_insecure_directory_is_rejected(self):
        self.root.chmod(0o755)
        with self.assertRaises(Denied):
            update_policy(self.path, "grant_peer", peer_ids=[42])
        self.root.chmod(0o700)

    def test_repository_policy_path_is_rejected(self):
        project=self.root/"project"
        project.mkdir(mode=0o700)
        (project/".git").mkdir(mode=0o700)
        private=project/"secrets"
        private.mkdir(mode=0o700)
        with self.assertRaises(Denied):
            update_policy(private/"policy.json","grant_peer",peer_ids=[42])

    def test_cli_grant_and_validate_do_not_print_peer_data(self):
        output=io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--policy",str(self.path),"grant-peer","--peer-id","42"]),0)
            self.assertEqual(main(["--policy",str(self.path),"validate"]),0)
        self.assertEqual(output.getvalue().splitlines(),["policy_updated","policy_valid"])


if __name__ == "__main__":
    unittest.main()
