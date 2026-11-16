"""Account isolation: temporary synthetic state, mock HTTP and in-process MCP only."""
import asyncio
from contextlib import AsyncExitStack
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import httpx

from whatsapp_assistant.accounts import read_catalogue, load_accounts
from whatsapp_assistant.auth import JWKSVerifier
from whatsapp_assistant.security import Denied
from whatsapp_assistant.server import BridgeClient, build_app, build_mcp
from test_whatsapp import CONFIG, signed, jwk


class AccountConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.rows = []
        for i, name in enumerate(("personal", "work")):
            directory = self.root / name
            state = directory / "state"
            state.mkdir(parents=True, mode=0o700); directory.chmod(0o700)
            resource = f"https://wa-{name}.example.test/mcp"
            self.rows.append({"account_id": name, "private_dir": str(directory), "resource": resource,
                "mcp_port": 8877 + i * 10, "bridge_port": 8878 + i * 10, "enable_write": i == 0})
            self.write(directory / "auth.json", {"issuer": CONFIG.issuer, "resource": resource,
                "jwks_url": CONFIG.jwks_url, "allowed_subjects": [f"fixture-{name}"]})
            self.write(directory / "bridge.json", {"account_id": name, "listen_port": 8878 + i * 10,
                "expected_account_jid": f"1000{i + 1}@s.whatsapp.net",
                "state_dir": str(state), "token_file": str(state / "bridge.token"),
                "key_file": str(state / "history.key"), "read_chats": ["10003@s.whatsapp.net"],
                "write_chats": ["10003@s.whatsapp.net"] if i == 0 else [], "write_enabled": i == 0,
                "per_minute": 1, "per_day": 20, "encrypted_volume_confirmed": True})
            for filename, value in [("account.id", name), ("bridge.token", str(i * 2 + 1) * 64), ("history.key", str(i * 2 + 2) * 64)]:
                p = state / filename; p.write_text(value); p.chmod(0o600)
        self.manifest = self.root / "accounts.json"
        self.save_manifest()

    def write(self, path, value):
        path.write_text(json.dumps(value)); path.chmod(0o600)

    def save_manifest(self):
        self.write(self.manifest, {"version": 1, "accounts": self.rows})

    def edit_bridge(self, name, **changes):
        path = self.root / name / "bridge.json"
        self.write(path, {**json.loads(path.read_text()), **changes})

    def test_valid_accounts_separate_policies_and_explicit_selection(self):
        a, b = load_accounts(self.manifest)
        self.assertEqual((a.account_id, b.account_id), ("personal", "work"))
        self.assertTrue(a.enable_write); self.assertFalse(b.enable_write)
        self.assertNotEqual(a.token_file, b.token_file)
        from whatsapp_assistant.accounts import launch
        with patch("whatsapp_assistant.server.require_runtime"), patch("whatsapp_assistant.server.serve", new_callable=AsyncMock) as serve:
            launch(b)
        args = serve.await_args.args[0]
        self.assertEqual((args.account_id, args.port, args.bridge_port), ("work", 8887, 8888))
        self.assertEqual(args.auth_config, b.auth_file)
        self.assertFalse(args.enable_write)

    def test_same_or_nested_storage_rejected_before_files(self):
        for value in (self.rows[0]["private_dir"], self.rows[0]["private_dir"] + "/nested"):
            self.rows[1]["private_dir"] = value; self.save_manifest()
            with self.assertRaisesRegex(Denied, "account_storage_conflict"): read_catalogue(self.manifest)

    def test_duplicate_names_resources_and_cross_role_ports_rejected(self):
        original = self.rows[1].copy()
        for key, value, code in [("account_id", "personal", "account_identity_conflict"),
                ("resource", self.rows[0]["resource"], "account_identity_conflict"),
                ("bridge_port", 8877, "account_port_conflict")]:
            self.rows[1] = {**original, key: value}; self.save_manifest()
            with self.assertRaisesRegex(Denied, code): read_catalogue(self.manifest)

    def test_invalid_alias_and_boolean_ports_rejected(self):
        original = self.rows[1].copy()
        for changes in ({"account_id": "../personal"}, {"mcp_port": True}, {"enable_write": "true"}, {"resource": "https://fixture.test/mcp\nmalicious"}):
            self.rows[1] = {**original, **changes}; self.save_manifest()
            with self.assertRaises(Denied): read_catalogue(self.manifest)

    def test_swapped_tokens_and_keys_rejected(self):
        p = self.root / "work/state/bridge.token"
        for source in (self.root / "personal/state/bridge.token", self.root / "personal/state/history.key"):
            p.write_bytes(source.read_bytes())
            with self.assertRaisesRegex(Denied, "account_secret_reused"): load_accounts(self.manifest)

    def test_swapped_state_binding_audience_and_bridge_port_rejected(self):
        binding = self.root / "work/state/account.id"; binding.write_text("personal")
        with self.assertRaisesRegex(Denied, "account_state_mismatch"): load_accounts(self.manifest)
        binding.write_text("work")
        self.edit_bridge("work", listen_port=8878)
        with self.assertRaisesRegex(Denied, "account_bridge_mismatch"): load_accounts(self.manifest)
        self.edit_bridge("work", listen_port=8888)
        auth = self.root / "work/auth.json"
        self.write(auth, {**json.loads(auth.read_text()), "resource": self.rows[0]["resource"]})
        with self.assertRaisesRegex(Denied, "account_audience_mismatch"): load_accounts(self.manifest)

    def test_same_phone_account_cannot_be_registered_twice(self):
        self.edit_bridge("work", expected_account_jid="10001@s.whatsapp.net")
        with self.assertRaisesRegex(Denied, "account_identity_reused"): load_accounts(self.manifest)

    def test_policy_and_write_mode_must_match_selected_account(self):
        self.edit_bridge("work", write_enabled=True)
        with self.assertRaisesRegex(Denied, "account_bridge_mismatch"): load_accounts(self.manifest)
        self.edit_bridge("work", write_enabled=False, write_chats=["99999@s.whatsapp.net"])
        with self.assertRaisesRegex(Denied, "invalid_account_policy"): load_accounts(self.manifest)

    def test_broad_access_is_explicit_and_isolated_per_account(self):
        self.edit_bridge("personal", read_access="all_chats", write_access="all_chats",
                         read_chats=[], write_chats=[], per_minute=10, per_day=200)
        a, b = load_accounts(self.manifest)
        self.assertTrue(a.enable_write)
        self.assertFalse(b.enable_write)
        self.edit_bridge("work", write_access="all_chats")
        with self.assertRaisesRegex(Denied, "invalid_account_policy"):
            load_accounts(self.manifest)
        self.edit_bridge("work", write_access="allowlist", read_access="everything")
        with self.assertRaisesRegex(Denied, "invalid_account_policy"):
            load_accounts(self.manifest)

    def test_private_paths_cannot_be_symlinked(self):
        state = self.root / "work/state"; moved = self.root / "moved"
        state.rename(moved); state.symlink_to(moved)
        with self.assertRaisesRegex(Denied, "unsafe_account_directory"): load_accounts(self.manifest)

    def test_container_preflight_checks_host_secrets_without_mounting_them(self):
        for name in ("personal", "work"):
            self.edit_bridge(name, state_dir="/state", token_file="/state/bridge.token", key_file="/state/history.key")
        self.assertEqual(len(load_accounts(self.manifest, container=True)), 2)
        with self.assertRaisesRegex(Denied, "account_bridge_mismatch"): load_accounts(self.manifest)


class MultiAccountHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def test_two_concurrent_mcp_connections_isolate_jwts_registry_and_read_results(self):
        configs = [replace(CONFIG, resource=f"https://wa-{name}.example.test/mcp",
                    allowed_subjects=(f"fixture-{name}",)) for name in ("personal", "work")]
        bridges = [AsyncMock(), AsyncMock()]
        for name, bridge in zip(("personal", "work"), bridges):
            bridge.call.return_value = {"messages": [{"text": f"fixture-{name}-body"}], "history_complete": False}
        verifiers = [JWKSVerifier(c, http=httpx.AsyncClient(transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"keys": [jwk()]})))) for c in configs]
        mcps = [build_mcp(b, c, v, account_id=name, port=port, enable_write=write)
            for b, c, v, name, port, write in zip(bridges, configs, verifiers, ("personal", "work"), (8877, 8887), (True, False))]
        apps = [build_app(m, c, port=p, enable_write=w)
            for m, c, p, w in zip(mcps, configs, (8877, 8887), (True, False))]
        async with AsyncExitStack() as stack:
            for verifier in verifiers: stack.push_async_callback(verifier.close)
            for mcp in mcps: await stack.enter_async_context(mcp.session_manager.run())
            clients = [await stack.enter_async_context(httpx.AsyncClient(transport=httpx.ASGITransport(
                app), base_url=c.resource.removesuffix("/mcp"))) for app, c in zip(apps, configs)]
            tokens = [signed(aud=c.resource, sub=c.allowed_subjects[0], scope="whatsapp:read whatsapp:send") for c in configs]
            async def rpc(i, method, params, token=None, host=None):
                headers = {"Accept": "application/json, text/event-stream", "Authorization": "Bearer " + (token or tokens[i])}
                if host: headers["Host"] = host
                return await clients[i].post("/mcp", headers=headers,
                    json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
            params = {"name": "read_history", "arguments": {"chat_id": "10003@s.whatsapp.net"}}
            responses = await asyncio.gather(rpc(0, "tools/call", params), rpc(1, "tools/call", params))
            self.assertIn("fixture-personal-body", responses[0].text)
            self.assertNotIn("fixture-work-body", responses[0].text)
            self.assertEqual(json.loads(responses[1].json()["result"]["content"][0]["text"])["account_id"], "work")
            counts = [b.call.await_count for b in bridges]
            for i in (0, 1):
                self.assertEqual((await rpc(i, "tools/call", params, token=tokens[1-i])).status_code, 401)
            self.assertEqual((await rpc(1, "tools/call", params, token=signed(
                aud=configs[1].resource, sub=configs[0].allowed_subjects[0]))).status_code, 401)
            self.assertEqual([b.call.await_count for b in bridges], counts)
            tools = [(await rpc(i, "tools/list", {})).json()["result"]["tools"] for i in (0, 1)]
            self.assertIn("send_text", {t["name"] for t in tools[0]})
            self.assertNotIn("send_text", {t["name"] for t in tools[1]})
            self.assertEqual((await rpc(1, "tools/list", {}, host="127.0.0.1:8877")).status_code, 421)
            self.assertEqual((await rpc(1, "tools/list", {}, host="127.0.0.1:8887")).status_code, 200)
            bridges[0].call.return_value = {"error": "bridge_unavailable"}
            self.assertIn("bridge_unavailable", (await rpc(0, "tools/call", params)).text)
            self.assertIn("fixture-work-body", (await rpc(1, "tools/call", params)).text)

    async def test_bridge_account_and_token_must_match_no_fallback_or_retry(self):
        seen = []
        def handler(r):
            seen.append(r)
            self.assertEqual(str(r.url), "http://127.0.0.1:8888/v1/call")
            self.assertEqual(r.headers["x-whatsapp-account"], "work")
            return httpx.Response(200, headers={"X-WhatsApp-Account": "personal"}, json={"messages": ["fixture-private"]})
        client = BridgeClient("b" * 64, httpx.AsyncClient(transport=httpx.MockTransport(handler)), account_id="work", port=8888)
        self.assertEqual(await client.call("history"), {"error": "bridge_account_mismatch"})
        self.assertEqual(await client.call("send_text", request_id="fixture_request_0001"),
            {"status": "unknown", "request_id": "fixture_request_0001"})
        self.assertEqual(len(seen), 2)
        await client.close()


if __name__ == "__main__":
    unittest.main()
