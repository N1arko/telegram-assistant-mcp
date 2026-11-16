"""WhatsApp acceptance tests. MockTransport and in-process ASGI only."""
import asyncio
import base64
from dataclasses import replace
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from whatsapp_assistant.auth import AuthConfig, JWKSVerifier, validate_claims
from whatsapp_assistant.security import Denied, private_file
from whatsapp_assistant.server import BridgeClient, build_app, build_mcp

CONFIG = AuthConfig("https://identity.example.test/", "https://wa.example.test/mcp",
                    "https://identity.example.test/.well-known/jwks.json", ("fixture-owner",))
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def claims(**kw):
    return {"iss": CONFIG.issuer, "aud": CONFIG.resource, "sub": "fixture-owner",
            "exp": int(time.time()) + 300, "scope": "whatsapp:read", **kw}


def signed(**kw):
    return jwt.encode(claims(**kw), KEY, algorithm="RS256", headers={"kid": "fixture-key"})


def jwk():
    return {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(KEY.public_key())),
            "kid": "fixture-key", "use": "sig", "alg": "RS256"}


class WhatsAppTransportTests(unittest.IsolatedAsyncioTestCase):
    enable_write = False

    async def asyncSetUp(self):
        self.bridge = AsyncMock()
        self.bridge.call.return_value = {"connected": False, "history_complete": False}
        self.seen_keys = []
        def fetch(req):
            self.seen_keys.append(req)
            return httpx.Response(200, json={"keys": [jwk()]})
        self.verifier = JWKSVerifier(CONFIG, http=httpx.AsyncClient(transport=httpx.MockTransport(fetch)))
        self.mcp = build_mcp(self.bridge, CONFIG, self.verifier, enable_write=self.enable_write)
        self.app = build_app(self.mcp, CONFIG, enable_write=self.enable_write)
        self.ready, self.stop = asyncio.Event(), asyncio.Event()
        async def lifespan():
            async with self.mcp.session_manager.run():
                self.ready.set()
                await self.stop.wait()
        self.task = asyncio.create_task(lifespan())
        await self.ready.wait()
        self.http = httpx.AsyncClient(transport=httpx.ASGITransport(self.app), base_url="https://wa.example.test")

    async def asyncTearDown(self):
        await self.http.aclose()
        self.stop.set()
        await self.task
        await self.verifier.close()

    async def rpc(self, method, params=None, token=True, headers=None):
        h = {"Accept": "application/json, text/event-stream"}
        if token:
            h["Authorization"] = "Bearer " + (signed() if token is True else token)
        h.update(headers or {})
        return await self.http.post("/mcp", headers=h,
            json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})

    async def test_metadata_and_mcp_initialize(self):
        r = await self.http.get("/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["resource"], CONFIG.resource)
        self.assertEqual(r.json()["scopes_supported"], ["whatsapp:read", "whatsapp:send"] if self.enable_write else ["whatsapp:read"])
        r = await self.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "fixture", "version": "1"}})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["result"]["serverInfo"]["name"], "personal-whatsapp")
        self.bridge.call.assert_not_called()

    async def test_missing_invalid_wrong_subject_and_scopes_before_bridge(self):
        for token in [False, "invalid", signed(sub="another-owner"), signed(exp=0),
                signed(aud="https://telegram.example.test/mcp"), signed(scope="telegram:read"),
                signed(scope="whatsapp:send"), signed(nbf=int(time.time()) + 90)]:
            r = await self.rpc("tools/call", {"name": "status", "arguments": {}}, token=token)
            self.assertEqual(r.status_code, 401)
            self.assertIn("resource_metadata", r.headers["www-authenticate"])
        self.bridge.call.assert_not_called()

    async def test_exact_registry_and_no_mutation_backdoors(self):
        r = await self.rpc("tools/list")
        tools = {t["name"]: t for t in r.json()["result"]["tools"]}
        expected = {"status", "list_chats", "read_history", "search_history", "get_media", "get_send_status", "resolve_recipients"}
        if self.enable_write:
            expected |= {"send_text", "send_media"}
        self.assertEqual(set(tools), expected)
        for name in ["mark_read", "typing", "delete_message", "react", "grant", "qr"]:
            r = await self.rpc("tools/call", {"name": name, "arguments": {}})
            self.assertTrue(r.json()["result"]["isError"])
        self.bridge.call.assert_not_called()
        for name in expected - {"send_text", "send_media"}:
            self.assertTrue(tools[name]["annotations"]["readOnlyHint"])

    async def test_history_cursor_preserved_and_no_jwt_forwarded(self):
        self.bridge.call.return_value = {"messages": [], "next_cursor": "fixture-cursor", "history_complete": False}
        r = await self.rpc("tools/call", {"name": "read_history", "arguments": {
            "chat_id": "10001@s.whatsapp.net", "limit": 3, "cursor": "fixture-cursor"}})
        self.assertFalse(r.json()["result"]["isError"])
        self.bridge.call.assert_awaited_once_with("history", chat_id="10001@s.whatsapp.net", limit=3, cursor="fixture-cursor")
        self.assertNotIn("authorization", self.seen_keys[0].headers)

    async def test_new_recipient_batch_and_invalid_numbers_before_bridge(self):
        phones = [f"+55119999000{i:02}" for i in range(10)]
        self.bridge.call.return_value = {"recipients": [{"registered": True,
            "chat_id": p[1:] + "@s.whatsapp.net"} for p in phones]}
        r = await self.rpc("tools/call", {"name": "resolve_recipients", "arguments": {"phone_numbers": phones}})
        self.assertFalse(r.json()["result"]["isError"])
        self.bridge.call.assert_awaited_once_with("resolve_recipients", phone_numbers=phones)
        self.bridge.call.reset_mock()
        for values in ([], ["not-a-phone"], phones * 3):
            r = await self.rpc("tools/call", {"name": "resolve_recipients", "arguments": {"phone_numbers": values}})
            self.assertTrue(r.json()["result"]["isError"])
        self.bridge.call.assert_not_called()

    async def test_recipient_unknown_is_null_and_distinct_from_confirmed_out(self):
        self.bridge.call.return_value = {"recipients": [
            {"phone_number": "+10001", "chat_id": "", "registered": None,
             "lookup_status": "unknown", "reason": "missing_result"},
            {"phone_number": "+10002", "chat_id": "", "registered": False,
             "lookup_status": "not_registered"},
        ], "lookup_complete": False}
        r = await self.rpc("tools/call", {"name": "resolve_recipients", "arguments": {
            "phone_numbers": ["+10001", "+10002"]}})
        value = json.loads(r.json()["result"]["content"][0]["text"])
        self.assertFalse(r.json()["result"]["isError"])
        self.assertIsNone(value["recipients"][0]["registered"])
        self.assertIs(value["recipients"][1]["registered"], False)
        self.assertFalse(value["lookup_complete"])
        self.assertNotEqual(value["recipients"][0]["lookup_status"], value["recipients"][1]["lookup_status"])

    async def test_selected_photo_document_and_audio_inline(self):
        for kind, mime, content_type in [("photo", "image/png", "image"),
                ("document", "application/pdf", "resource"), ("audio", "audio/ogg", "audio")]:
            self.bridge.call.return_value = {"data_base64": base64.b64encode(b"fixture bytes").decode(),
                "media_kind": kind, "mime_type": mime, "filename": "fixture"}
            r = await self.rpc("tools/call", {"name": "get_media", "arguments": {
                "chat_id": "10001@s.whatsapp.net", "message_id": "fixture-id"}})
            self.assertEqual(r.json()["result"]["content"][0]["type"], content_type)
        self.assertEqual(self.bridge.call.await_count, 3)

    async def test_selected_media_base64_fallback(self):
        import hashlib
        raw = b"fixture audio bytes"
        self.bridge.call.return_value = {"data_base64": base64.b64encode(raw).decode(),
            "media_kind": "audio", "mime_type": "audio/ogg"}
        r = await self.rpc("tools/call", {"name": "get_media", "arguments": {
            "chat_id": "10001@s.whatsapp.net", "message_id": "fixture-id",
            "output_format": "base64"}})
        result = r.json()["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["content"][0]["type"], "text")
        value = json.loads(result["content"][0]["text"])
        self.assertEqual(base64.b64decode(value["data_base64"]), raw)
        self.assertEqual(value["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(value["size_bytes"], len(raw))
        self.assertEqual(value["mime_type"], "audio/ogg")
        self.bridge.call.assert_awaited_once_with("get_media", chat_id="10001@s.whatsapp.net", message_id="fixture-id")

    async def test_base64_fallback_rejects_invalid_media(self):
        for data in ["!not-base64!", "", base64.b64encode(b"x" * (5 * 1024 * 1024 + 1)).decode()]:
            self.bridge.call.return_value = {"data_base64": data, "media_kind": "audio", "mime_type": "audio/ogg"}
            r = await self.rpc("tools/call", {"name": "get_media", "arguments": {
                "chat_id": "10001@s.whatsapp.net", "message_id": "fixture-id", "output_format": "base64"}})
            self.assertTrue(r.json()["result"]["isError"])
            self.assertNotIn("data_base64", r.text)

    async def test_errors_and_schema_do_not_echo_arguments(self):
        for args in [{"chat_id": "fixture-secret-invalid-chat"},
                {"chat_id": "10001@s.whatsapp.net", "limit": True},
                {"chat_id": "10001@s.whatsapp.net", "limit": 21}]:
            r = await self.rpc("tools/call", {"name": "read_history", "arguments": args})
            self.assertTrue(r.json()["result"]["isError"])
            self.assertNotIn("fixture-secret", r.text)
        self.bridge.call.assert_not_called()

    async def test_host_origin_and_body_limits(self):
        for headers, expected in [({"Host": "evil.test"}, 421), ({"Origin": "https://evil.test"}, 403)]:
            r = await self.rpc("tools/list", headers=headers)
            self.assertEqual(r.status_code, expected)
        r = await self.http.post("/mcp", content=b"x" * 65537)
        self.assertEqual(r.status_code, 400)  # malformed JSON is rejected before auth
        self.bridge.call.assert_not_called()

    async def test_read_tokens_cannot_send_even_when_write_registry_enabled(self):
        r = await self.rpc("tools/call", {"name": "send_text", "arguments": {
            "chat_id": "10001@s.whatsapp.net", "request_id": "fixture_request_0001", "text": "fixture"}})
        self.assertTrue(r.json()["result"]["isError"])
        self.bridge.call.assert_not_called()


class WhatsAppWriteTransportTests(WhatsAppTransportTests):
    enable_write = True

    async def test_send_exact_request_key_and_unknown_result(self):
        self.bridge.call.return_value = {"status": "unknown", "message_id": "fixture-id"}
        args = {"chat_id": "10001@s.whatsapp.net", "request_id": "fixture_request_0001", "text": "fixture", "reply_to": "previous"}
        r = await self.rpc("tools/call", {"name": "send_text", "arguments": args}, token=signed(scope="whatsapp:read whatsapp:send"))
        value = json.loads(r.json()["result"]["content"][0]["text"])
        self.assertEqual(value["status"], "unknown")
        self.bridge.call.assert_awaited_once_with("send_text", **args)

    async def test_no_urls_or_local_paths_as_media_source(self):
        args = {"chat_id": "10001@s.whatsapp.net", "request_id": "fixture_request_0001",
            "data_base64": "https://fixture.invalid/file", "media_kind": "document", "mime_type": "application/pdf", "filename": "fixture.pdf"}
        # Validation of base64/signatures is a second barrier in the bridge.
        self.bridge.call.return_value = {"error": "invalid_media"}
        r = await self.rpc("tools/call", {"name": "send_media", "arguments": args}, token=signed(scope="whatsapp:read whatsapp:send"))
        self.assertIn("invalid_media", r.text)


class WhatsAppClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_timeout_unknown_exactly_one_attempt_and_no_body_leak(self):
        seen = []
        def fail(request):
            seen.append(request)
            raise httpx.ReadTimeout("fixture private body", request=request)
        client = BridgeClient("a" * 64, httpx.AsyncClient(transport=httpx.MockTransport(fail)))
        value = await client.call("send_text", chat_id="10001@s.whatsapp.net", request_id="fixture_request_0001", text="fixture")
        self.assertEqual(value, {"status": "unknown", "request_id": "fixture_request_0001"})
        self.assertEqual(len(seen), 1)
        self.assertEqual(str(seen[0].url), "http://127.0.0.1:8878/v1/call")
        self.assertEqual(seen[0].headers["authorization"], "Bearer " + "a" * 64)
        await client.close()

    async def test_redirect_and_invalid_errors_are_not_exposed(self):
        for response in [httpx.Response(302, headers={"location": "https://fixture.invalid"}),
                httpx.Response(200, json={"error": "fixture private body"}, headers={"X-WhatsApp-Account": "default"}),
                httpx.Response(200, text="fixture private body", headers={"X-WhatsApp-Account": "default"})]:
            client = BridgeClient("a" * 64, httpx.AsyncClient(transport=httpx.MockTransport(lambda r: response)))
            self.assertEqual(await client.call("history"), {"error": "bridge_unavailable"})
            await client.close()

    async def test_auth_rejects_token_headers_and_wrong_signatures(self):
        verifier = JWKSVerifier(CONFIG, http=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"keys": [jwk()]}))))
        other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        for token in [jwt.encode(claims(), other, algorithm="RS256", headers={"kid": "fixture-key"}),
                jwt.encode(claims(), KEY, algorithm="RS256", headers={"kid": "fixture-key", "jku": "https://fixture.invalid"}),
                jwt.encode(claims(), "x" * 32, algorithm="HS256", headers={"kid": "fixture-key"})]:
            self.assertIsNone(await verifier.verify_token(token))
        self.assertIsNotNone(await verifier.verify_token(signed()))
        await verifier.close()

    def test_owner_only_private_files_and_auth_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "config"
            p.write_text("fixture");p.chmod(0o644)
            with self.assertRaises(Denied): private_file(p)
            p.chmod(0o600)
            self.assertEqual(private_file(p), b"fixture")
            link = Path(tmp) / "link";link.symlink_to(p)
            with self.assertRaises(OSError): private_file(link)
            os.link(p, Path(tmp) / "hardlink")
            with self.assertRaises(Denied): private_file(p)
        for kw in [{"jwks_url": "https://other.example.test/jwks"}, {"allowed_subjects": ()}, {"algorithms": ("HS256",)}]:
            with self.assertRaises(Denied): replace(CONFIG, **kw)
        for kw in [{"scope": "telegram:read"}, {"sub": "other"}, {"exp": True}, {"nbf": True}]:
            self.assertIsNone(validate_claims(claims(**kw), CONFIG, time.time()))


if __name__ == "__main__":
    unittest.main()
