import asyncio
import io
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import jwt

from telegram_assistant.server import (
    BootstrapApp, BootstrapConfig, build_bootstrap_app, serve_bootstrap,
)
from telegram_assistant.security import Denied


CONFIG = BootstrapConfig(
    issuer="https://tenant.example.test/",
    resource="https://telegram.example.test/mcp",
)


class BootstrapConfigTests(unittest.TestCase):
    def test_requires_exact_public_resource_and_read_scope(self):
        for changes in [
            {"issuer": "http://identity.example.test/"},
            {"issuer": "https://identity.example.test/extra/"},
            {"resource": "http://telegram.example.test/mcp"},
            {"resource": "https://telegram.example.test/other"},
            {"scopes": ["telegram:read", "telegram:send"]},
            {"scopes": "telegram:read"},
        ]:
            with self.subTest(changes=changes), self.assertRaises(Denied):
                BootstrapConfig(**{**CONFIG.__dict__, **changes})

    def test_loads_owner_only_bootstrap_config(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bootstrap.json"
            path.write_text(json.dumps({
                "issuer": CONFIG.issuer,
                "resource": CONFIG.resource,
                "scopes": ["telegram:read"],
            }))
            path.chmod(0o600)
            self.assertEqual(BootstrapConfig.load(path), CONFIG)


class BootstrapTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.app = build_bootstrap_app(CONFIG)
        self.http = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="https://telegram.example.test",
        )

    async def asyncTearDown(self):
        await self.http.aclose()

    async def test_public_metadata_has_only_read_scope(self):
        response = await self.http.get(BootstrapApp.metadata_path)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            "resource": CONFIG.resource,
            "authorization_servers": [CONFIG.issuer],
            "scopes_supported": ["telegram:read"],
        })
        self.assertEqual(response.headers["cache-control"], "no-store")

    async def test_every_mcp_request_is_401_with_discovery_challenge(self):
        requests = [
            ("POST", {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            ("POST", {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
            ("POST", {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_dialogs"}}),
            ("DELETE", None),
        ]
        for method, body in requests:
            response = await self.http.request(method, "/mcp", json=body)
            self.assertEqual(response.status_code, 401, response.text)
            self.assertEqual(response.json(), {"error": "unauthorized"})
            self.assertEqual(response.headers["www-authenticate"],
                'Bearer resource_metadata="https://telegram.example.test/.well-known/oauth-protected-resource/mcp", scope="telegram:read"')
        malformed = await self.http.post("/mcp", content=b"not-json")
        self.assertEqual(malformed.status_code, 401)
        self.assertIn("resource_metadata", malformed.headers["www-authenticate"])

    async def test_missing_invalid_and_validly_shaped_tokens_all_rejected(self):
        fake_valid_jwt = jwt.encode({
            "iss": CONFIG.issuer, "aud": CONFIG.resource, "sub": "opaque-user",
            "scope": "telegram:read", "exp": 9999999999,
        }, "bootstrap-test-key-with-at-least-thirty-two-bytes", algorithm="HS256")
        for token in [None, "invalid-token", fake_valid_jwt]:
            headers = {} if token is None else {"Authorization": f"Bearer {token}"}
            response = await self.http.post("/mcp", headers=headers,
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
            self.assertEqual(response.status_code, 401)
            self.assertIn("resource_metadata", response.headers["www-authenticate"])

    async def test_metadata_is_public_but_other_paths_are_not_exposed(self):
        response = await self.http.get(BootstrapApp.metadata_path,
                                       headers={"Authorization": "Bearer invalid"})
        self.assertEqual(response.status_code, 200)
        for path in ["/", "/health", "/openapi.json", "/mcp/extra"]:
            response = await self.http.get(path)
            self.assertEqual(response.status_code, 404, path)
        response = await self.http.post(BootstrapApp.metadata_path)
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.headers["allow"], "GET")

    async def test_host_origin_and_request_size_limits(self):
        response = await self.http.get(BootstrapApp.metadata_path,
                                       headers={"Host": "evil.example.test"})
        self.assertEqual(response.status_code, 421)
        response = await self.http.get(BootstrapApp.metadata_path,
                                       headers={"Origin": "https://evil.example.test"})
        self.assertEqual(response.status_code, 403)
        response = await self.http.post("/mcp", content=b"x" * 65537)
        self.assertEqual(response.status_code, 413)


class BootstrapRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_runtime_needs_only_bootstrap_config_and_never_initializes_telegram(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bootstrap.json"
            path.write_text(json.dumps({
                "issuer": CONFIG.issuer,
                "resource": CONFIG.resource,
                "scopes": ["telegram:read"],
            }))
            path.chmod(0o600)
            args = Namespace(bootstrap_config=path, container_network=False)
            with patch("uvicorn.Server") as server_type:
                server = server_type.return_value
                server.serve = AsyncMock()
                await serve_bootstrap(args)
                server.serve.assert_awaited_once()
                self.assertEqual(server_type.call_args.args[0].host, "127.0.0.1")
                app = server_type.call_args.args[0].app
                self.assertIsInstance(app.app, BootstrapApp)

    def test_explicit_bootstrap_mode_dispatch_does_not_require_live_paths(self):
        with patch("sys.argv", ["telegram-assistant-mcp", "--mode", "bootstrap",
                                "--bootstrap-config", "/bootstrap.json"]), \
             patch("telegram_assistant.server.serve_bootstrap", AsyncMock()) as bootstrap:
            from telegram_assistant.server import main
            main()
            bootstrap.assert_awaited_once()

    async def test_bootstrap_rejects_live_configuration_arguments(self):
        with patch("sys.argv", ["telegram-assistant-mcp", "--mode", "bootstrap",
                                "--bootstrap-config", "/bootstrap.json",
                                "--telegram-config", "/must-not-be-read"]), \
             patch("telegram_assistant.server.serve_bootstrap", AsyncMock()) as bootstrap, \
             patch("sys.stderr", new_callable=io.StringIO):
            from telegram_assistant.server import main
            with self.assertRaises(SystemExit) as error:
                main()
            self.assertEqual(error.exception.code, 2)
            bootstrap.assert_not_awaited()
