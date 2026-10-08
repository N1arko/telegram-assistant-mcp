import json
import asyncio
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
from telegram_assistant.auth import AuthConfig, JWKSVerifier, validate_claims
from telegram_assistant.auth_diagnostics import Auth401Diagnostics
from telegram_assistant.server import RequestLimits, build_app, build_mcp
from telegram_assistant.service import MAX_BYTES, SCOPES, Service
from telegram_assistant.media import ImageResult, MAX_MEDIA_RESPONSE_BYTES
from test_service import Fake


CONFIG=AuthConfig(issuer="https://identity.example.test/",resource="https://telegram.example.test/mcp",
                  jwks_url="https://identity.example.test/.well-known/jwks.json",allowed_subjects=("owner-123",))
KEY=rsa.generate_private_key(public_exponent=65537,key_size=2048)
KEY2=rsa.generate_private_key(public_exponent=65537,key_size=2048)
def jwk(key=KEY,kid="key-1"):
    return {**json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())),"kid":kid,"use":"sig","alg":"RS256"}
def claims(**kw):
    return {"iss":CONFIG.issuer,"aud":CONFIG.resource,"sub":"owner-123",
            "exp":int(time.time())+300,"scope":"telegram:read","azp":"mcp-client",**kw}
def signed(data=None,key=KEY,kid="key-1",**headers):
    return jwt.encode(claims() if data is None else data,key,algorithm="RS256",headers={"kid":kid,**headers})

class AuthTests(unittest.IsolatedAsyncioTestCase):
    def test_claims_invalid_variants(self):
        self.assertIsNotNone(validate_claims(claims(),CONFIG,time.time()))
        variants=[{"iss":"https://wrong.test/"},{"aud":"https://wrong.test/mcp"},
                  {"aud":[CONFIG.resource,1]},{"sub":"other-user"},{"sub":None},
                  {"exp":0},{"exp":True},{"exp":"123"},{"scope":"telegram:send"},
                  {"scope":None},{"azp":None},{"nbf":int(time.time())+60},{"nbf":True}]
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertIsNone(validate_claims(claims(**variant),CONFIG,time.time()))
        self.assertIsNotNone(validate_claims(claims(aud=[CONFIG.resource]),CONFIG,time.time()))
        for name in ["iss","aud","sub","exp","scope"]:
            data=claims(); del data[name]
            self.assertIsNone(validate_claims(data,CONFIG,time.time()))

    async def test_fetch_bounds_no_token_disclosure(self):
        seen=[]
        def handler(request):
            seen.append(request)
            return httpx.Response(200,json={"keys":[jwk()]})
        verifier=JWKSVerifier(CONFIG,http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        raw=signed(); token=await verifier.verify_token(raw)
        self.assertEqual(token.resource,CONFIG.resource)
        self.assertEqual(token.scopes,["telegram:read"])
        await verifier.verify_token(raw)
        self.assertEqual(len(seen),1)
        self.assertEqual(str(seen[0].url),CONFIG.jwks_url)
        self.assertEqual(seen[0].method,"GET")
        self.assertNotIn("authorization",seen[0].headers)
        self.assertNotIn(raw,str(seen[0].headers)+str(seen[0].url)+str(seen[0].content))
        await verifier.close()
        for response in [httpx.Response(302),httpx.Response(500),httpx.Response(200,content="not json"),
                         httpx.Response(200,content="x"*65537),httpx.Response(200,json={"keys":[]}),
                         httpx.Response(200,json={"keys":[jwk(),jwk()]}),
                         httpx.Response(200,json={"keys":[jwk(rsa.generate_private_key(public_exponent=65537,key_size=1024))]})]:
            verifier=JWKSVerifier(CONFIG,http=httpx.AsyncClient(transport=httpx.MockTransport(lambda req:response)))
            self.assertIsNone(await verifier.verify_token(raw))
            self.assertIsNone(await verifier.verify_token("x"*8193))
            await verifier.close()

    async def test_signature_algorithms_claims_and_headers(self):
        calls=[]
        def handler(req):
            calls.append(req); return httpx.Response(200,json={"keys":[jwk()]})
        verifier=JWKSVerifier(CONFIG,http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
        self.assertIsNotNone(await verifier.verify_token(signed()))
        for raw in [signed(key=KEY2),signed(claims(exp=0)),signed(claims(sub="other")),
                    signed(claims(iss="https://wrong.test/")),signed(claims(aud="other")),
                    signed(claims(nbf=int(time.time())+60)),signed(claims(scope="telegram:send")),
                    signed(jku="https://evil.test"),signed(crit=["unknown"]),
                    jwt.encode(claims(),"x"*32,algorithm="HS256",headers={"kid":"key-1"}),
                    jwt.encode(claims(),"",algorithm="none",headers={"kid":"key-1"}),"broken"]:
            self.assertIsNone(await verifier.verify_token(raw))
        self.assertEqual(len(calls),1)
        await verifier.close()

    async def test_rotation_expiry_failed_refresh_and_singleflight(self):
        now=[100.0]; keys=[[jwk()]]; status=[200]; calls=[]
        def handler(req):
            calls.append(req); return httpx.Response(status[0],json={"keys":keys[0]})
        verifier=JWKSVerifier(CONFIG,http=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
                              monotonic=lambda:now[0],cache_seconds=60,refresh_seconds=10)
        self.assertIsNotNone(await verifier.verify_token(signed()))
        unknown=signed(key=KEY2,kid="key-2")
        self.assertIsNone(await verifier.verify_token(unknown))
        self.assertEqual(len(calls),1)
        now[0]+=11; keys[0]=[jwk(KEY2,"key-2")]
        results=await asyncio.gather(*[verifier.verify_token(unknown) for _ in range(8)])
        self.assertTrue(all(results)); self.assertEqual(len(calls),2)
        self.assertIsNone(await verifier.verify_token(signed()))
        now[0]+=61; status[0]=500
        self.assertIsNone(await verifier.verify_token(unknown))
        self.assertIsNone(await verifier.verify_token(unknown))
        self.assertEqual(len(calls),3)
        await verifier.close()

    async def test_token_expiry_not_cached(self):
        now=[time.time()]
        verifier=JWKSVerifier(CONFIG,http=httpx.AsyncClient(transport=httpx.MockTransport(
            lambda req:httpx.Response(200,json={"keys":[jwk()]}))),clock=lambda:now[0])
        raw=signed(claims(exp=int(now[0])+10))
        self.assertIsNotNone(await verifier.verify_token(raw))
        now[0]+=11; self.assertIsNone(await verifier.verify_token(raw))
        await verifier.close()

    def test_config_rejects_untrusted_endpoints_and_algorithms(self):
        from dataclasses import replace
        from telegram_assistant.security import Denied
        for kw in [{"jwks_url":"http://id.test/jwks"},{"jwks_url":"https://other.test/jwks"},
                   {"allowed_subjects":"owner-123"},{"allowed_subjects":[]},{"algorithms":["HS256"]}]:
            with self.assertRaises(Denied):replace(CONFIG,**kw)


class TransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.fake=Fake()
        self.fake.history=AsyncMock(wraps=self.fake.history)
        self.jwks_calls=0
        def fetch_keys(request):
            self.jwks_calls+=1
            return httpx.Response(200,json={"keys":[jwk()]})
        self.verifier=JWKSVerifier(CONFIG,http=httpx.AsyncClient(transport=httpx.MockTransport(fetch_keys)))
        self.service=Service(self.fake)
        self.mcp=build_mcp(self.service,CONFIG,self.verifier,read_only=getattr(self,"read_only",False))
        self.app=build_app(self.mcp,CONFIG,read_only=getattr(self,"read_only",False))
        self.ready = asyncio.Event()
        self.stop = asyncio.Event()
        async def manage_lifespan():
            async with self.mcp.session_manager.run():
                self.ready.set()
                await self.stop.wait()
        self.lifespan_task = asyncio.create_task(manage_lifespan())
        await self.ready.wait()
        self.http=httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app),base_url="https://telegram.example.test")
        self.counter=0
    async def asyncTearDown(self):
        await self.http.aclose()
        self.stop.set()
        await self.lifespan_task
        await self.verifier.close()
    async def rpc(self,method,params=None,token="fake-read",**kw):
        self.counter+=1
        headers={"Accept":"application/json, text/event-stream"}
        if token in ("fake-read","fake-write"):
            token=signed(claims(scope="telegram:read telegram:send" if token=="fake-write" else "telegram:read"))
        if token:headers["Authorization"]=f"Bearer {token}"
        headers.update(kw.get("headers",{}))
        return await self.http.post("/mcp",headers=headers,json={"jsonrpc":"2.0","id":self.counter,
                                   "method":method,"params":params or {}})
    async def test_all_mcp_methods_require_auth(self):
        for method,params in [("initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1"}}),
            ("tools/list",{}),("tools/call",{"name":"get_history","arguments":{"peer_id":42}}),
            ("tools/call",{"name":"scan_updates","arguments":{"limit":1}})]:
            for token in [None,"invalid"]:
                response=await self.rpc(method,params,token=token)
                self.assertEqual(response.status_code,401,response.text)
                self.assertIn("resource_metadata",response.headers["www-authenticate"])
        self.fake.history.assert_not_awaited()
        self.fake.send.assert_not_awaited()

    async def test_401_diagnostics_are_anonymous_and_keep_oauth_challenge(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "auth-401.sqlite"
            diagnostics = Auth401Diagnostics(path, int(time.time()) + 3600)
            app = build_app(self.mcp, CONFIG, diagnostics=diagnostics)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                         base_url="https://telegram.example.test") as client:
                body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
                expired = signed(claims(exp=int(time.time()) - 1))
                wrong_audience = signed(claims(aud="https://wrong.test/mcp"))
                for raw in (None, expired, wrong_audience):
                    headers = {"Accept": "application/json, text/event-stream"}
                    if raw is not None:
                        headers["Authorization"] = f"Bearer {raw}"
                    response = await client.post("/mcp", json=body, headers=headers)
                    self.assertEqual(response.status_code, 401)
                    self.assertIn("resource_metadata", response.headers["www-authenticate"])
                    self.assertRegex(response.headers["x-mcp-diag-id"], r"^[0-9a-f]{16}$")
                healthy = await client.post("/mcp", json=body, headers={
                    "Accept": "application/json, text/event-stream",
                    "Authorization": f"Bearer {signed()}"})
                self.assertEqual(healthy.status_code, 200)
                self.assertNotIn("x-mcp-diag-id", healthy.headers)
            with sqlite3.connect(path) as db:
                rows = db.execute("SELECT request_id, status, reason FROM auth_401 ORDER BY rowid").fetchall()
            self.assertEqual([row[2] for row in rows], ["missing", "expired", "claims"])
            self.assertTrue(all(row[1] == 401 for row in rows))
            self.assertNotIn(expired.encode(), path.read_bytes())
            self.assertNotIn(wrong_audience.encode(), path.read_bytes())
            self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)

    async def test_jwks_failure_is_distinct_from_invalid_claims(self):
        with tempfile.TemporaryDirectory() as folder:
            diagnostics = Auth401Diagnostics(Path(folder) / "auth-401.sqlite", int(time.time()) + 3600)
            failing = JWKSVerifier(CONFIG, http=httpx.AsyncClient(transport=httpx.MockTransport(
                lambda req: httpx.Response(503))))
            mcp = build_mcp(self.service, CONFIG, failing)
            app = build_app(mcp, CONFIG, diagnostics=diagnostics)
            ready, stop = asyncio.Event(), asyncio.Event()
            async def lifespan():
                async with mcp.session_manager.run():
                    ready.set()
                    await stop.wait()
            task = asyncio.create_task(lifespan())
            await ready.wait()
            try:
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                             base_url="https://telegram.example.test") as client:
                    response = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1,
                        "method": "tools/list", "params": {}}, headers={
                        "Accept": "application/json, text/event-stream",
                        "Authorization": f"Bearer {signed()}"})
                self.assertEqual(response.status_code, 401)
                with sqlite3.connect(diagnostics.path) as db:
                    self.assertEqual(db.execute("SELECT reason FROM auth_401").fetchone()[0], "jwks")
            finally:
                stop.set()
                await task
                await failing.close()


    async def test_metadata_and_initialize(self):
        metadata=await self.http.get("/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(metadata.status_code,200,metadata.text)
        self.assertEqual(metadata.json()["resource"],CONFIG.resource)
        self.assertEqual(metadata.json()["authorization_servers"],[CONFIG.issuer])
        self.assertEqual(metadata.json()["scopes_supported"],["telegram:read","telegram:send"])
        response=await self.rpc("initialize",{"protocolVersion":"2025-06-18","capabilities":{},
                                               "clientInfo":{"name":"test","version":"1"}})
        self.assertEqual(response.status_code,200,response.text)
        self.assertIn("result",response.json())
    async def test_exact_registry_and_no_resources_prompts(self):
        response=await self.rpc("tools/list")
        self.assertEqual(response.status_code,200,response.text)
        names={t["name"] for t in response.json()["result"]["tools"]}
        self.assertEqual(names,{"list_dialogs","get_history","search_messages","get_reply_context",
                               "scan_updates","view_photo","transcribe_audio","send_message","send_media"})
        for name in ["set_policy","edit_message","delete_message","mark_as_read","download_media","transcribe_voice"]:
            result=await self.rpc("tools/call",{"name":name,"arguments":{}})
            self.assertTrue(result.json()["result"]["isError"])
        self.assertEqual(await self.mcp.list_resources(),[])
        self.assertEqual(await self.mcp.list_prompts(),[])
    async def test_photo_returns_native_image_with_separate_bounded_envelope(self):
        preview=b"\xff\xd8\xff" + b"p" * (200 * 1024 - 3)
        self.service.view_photo=AsyncMock(return_value=ImageResult(preview))
        response=await self.rpc("tools/call",{"name":"view_photo",
            "arguments":{"peer_id":42,"message_id":9}})
        self.assertEqual(response.status_code,200,response.text[:200])
        self.assertGreater(len(response.content),MAX_BYTES)
        self.assertLessEqual(len(response.content),MAX_MEDIA_RESPONSE_BYTES)
        item=response.json()["result"]["content"][0]
        self.assertEqual(item["type"],"image")
        self.assertEqual(item["mimeType"],"image/jpeg")
        import base64
        self.assertEqual(base64.b64decode(item["data"]),preview)

    async def test_non_photo_tool_keeps_the_48k_asgi_response_cap(self):
        body=b'{"oversized":"' + b"x" * (MAX_BYTES + 1024) + b'"}'
        sent=[]
        async def app(scope, receive, send):
            await send({"type":"http.response.start","status":200,"headers":[]})
            await send({"type":"http.response.body","body":body})
        async def receive():
            return {"type":"http.request","body":b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_history"}}',"more_body":False}
        async def send(event):
            sent.append(event)
        await RequestLimits(app)({"type":"http","path":"/mcp","method":"POST","headers":[]},receive,send)
        self.assertEqual(sent[0]["status"],503)
        self.assertEqual(sent[-1]["body"],b'{"error":"request_rejected"}')
    async def test_history_over_actual_sdk_no_ports(self):
        response=await self.rpc("tools/call",{"name":"get_history","arguments":{"peer_id":42,"limit":3}})
        self.assertEqual(response.status_code,200,response.text)
        payload=json.loads(response.json()["result"]["content"][0]["text"])
        self.assertEqual([m["message_id"] for m in payload["messages"]],[12,11,10])
        self.fake.history.assert_awaited_once()
        self.fake.read_receipt.assert_not_awaited()

    async def test_scan_updates_transport_uses_read_scope_and_cursor_schema(self):
        sample={"messages":[],"next_cursor":"synthetic-cursor","catalogue_complete":False,
                "scan_truncated":False,"coverage_restarted":False,"queued_peers":0,
                "coverage_complete":False,"untrusted_content":True}
        self.service.scan_updates=AsyncMock(return_value=sample)
        response=await self.rpc("tools/call",{"name":"scan_updates",
            "arguments":{"limit":1,"cursor":"previous-cursor"}})
        self.assertEqual(response.status_code,200,response.text)
        payload=json.loads(response.json()["result"]["content"][0]["text"])
        self.assertEqual(payload,sample)
        self.service.scan_updates.assert_awaited_once_with(limit=1,cursor="previous-cursor")
    async def test_scope_and_policy_deny(self):
        for token,code in [("fake-read","send_scope_required"),("fake-write","send_denied")]:
            response=await self.rpc("tools/call",{"name":"send_message","arguments":{"peer_id":42,"text":"test"}},token=token)
            self.assertEqual(json.loads(response.json()["result"]["content"][0]["text"])["error"],code)
        self.fake.send.assert_not_awaited()
        for token,code in [("fake-read","send_scope_required"),("fake-write","send_denied")]:
            response=await self.rpc("tools/call",{"name":"send_media","arguments":{
                "peer_id":42,"items":[{"media_type":"document","data_base64":"eA=="}]}},token=token)
            self.assertEqual(json.loads(response.json()["result"]["content"][0]["text"])["error"],code)
        self.fake.send_media_files.assert_not_awaited()
        self.assertEqual(self.jwks_calls,1)  # Public-key cache; signatures/claims checked each request.

    async def test_send_media_tool_uses_inline_base64_and_existing_write_scope(self):
        import base64, tempfile
        from pathlib import Path
        from telegram_assistant.security import Grant, Policy, Quotas
        temporary=tempfile.TemporaryDirectory()
        quotas=Quotas(Path(temporary.name)/"quotas.sqlite")
        self.service.quotas=quotas
        self.service.policy=Policy([Grant(42, int(time.time())+300, 100, 1, 2)])
        self.fake.send_media_files.return_value=[88]
        response=await self.rpc("tools/call",{"name":"send_media","arguments":{
            "peer_id":42,"items":[{"media_type":"document","filename":"note.pdf",
                "caption":"inline bytes","data_base64":base64.b64encode(
                    b"%PDF-1.7\n"+b"synthetic-"*5000).decode()}]}},token="fake-write")
        self.assertEqual(response.status_code,200,response.text[:300])
        result=response.json()["result"]
        payload=json.loads(result["content"][0]["text"])
        self.assertEqual(payload["message_ids"],[88])
        self.assertEqual(payload["media_count"],1)
        self.fake.send_media_files.assert_awaited_once()
        quotas.close()
        temporary.cleanup()
    async def test_strict_numeric_peer(self):
        for peer in [True,"42","@name"]:
            response=await self.rpc("tools/call",{"name":"get_history","arguments":{"peer_id":peer}})
            self.assertTrue(response.json()["result"]["isError"])
        self.fake.history.assert_not_awaited()
    async def test_body_headers_and_rebinding_bounds(self):
        response=await self.http.post("/mcp",content=b"x"*65537)
        self.assertEqual(response.status_code,413)
        response=await self.http.post("/mcp",headers={"X-Large":"x"*17000},content=b"{}")
        self.assertEqual(response.status_code,431)
        for headers in [{"Host":"evil.example.test"},{"Origin":"https://evil.example.test"}]:
            response=await self.rpc("tools/list",headers=headers)
            self.assertIn(response.status_code,[403,421],response.text)
    async def test_sdk_validation_does_not_echo_input(self):
        secret="MESSAGE_CONTENT_NOT_FOR_DIAGNOSTICS"
        response=await self.rpc("tools/call",{"name":"get_history","arguments":{"peer_id":secret}})
        self.assertNotIn(secret,response.text)
        self.assertEqual(json.loads(response.json()["result"]["content"][0]["text"])["error"],"invalid_tool_call")
    async def test_wire_response_size_and_cursor_with_escaping(self):
        from test_service import msg
        from telegram_assistant.service import MAX_BYTES
        self.fake.items=[msg(i,text='"\\\n😀'*1000) for i in range(50,0,-1)]
        response=await self.rpc("tools/call",{"name":"get_history","arguments":{"peer_id":42,"limit":50}})
        self.assertEqual(response.status_code,200,response.text[:200])
        self.assertLessEqual(len(response.content),MAX_BYTES)
        data=json.loads(response.json()["result"]["content"][0]["text"])
        self.assertEqual(data["next_before_id"],data["messages"][-1]["message_id"])
    async def test_long_rpc_id_rejected(self):
        response=await self.http.post("/mcp",headers={"Authorization":"Bearer fake-read","Accept":"application/json, text/event-stream"},
             json={"jsonrpc":"2.0","id":"x"*200,"method":"tools/list"})
        self.assertEqual(response.status_code,400)


class MiddlewareTests(unittest.IsolatedAsyncioTestCase):
    async def test_only_send_media_may_use_large_request_body(self):
        body=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"send_media","arguments":{"filler":"x"*70000}}}).encode()
        received=[]
        async def app(scope,receive,send):
            received.append((await receive())["body"])
            await send({"type":"http.response.start","status":200,"headers":[]})
            await send({"type":"http.response.body","body":b"ok"})
        async def receive():
            return {"type":"http.request","body":body,"more_body":False}
        sent=[]
        async def send(event): sent.append(event)
        await RequestLimits(app)({"type":"http","path":"/mcp","method":"POST","headers":[]},receive,send)
        self.assertEqual(received,[body])
        self.assertEqual(sent[0]["status"],200)

        body=json.dumps({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"get_history","arguments":{"filler":"x"*70000}}}).encode()
        async def receive_nonmedia():
            return {"type":"http.request","body":body,"more_body":False}
        sent=[]
        await RequestLimits(app)({"type":"http","path":"/mcp","method":"POST","headers":[]},receive_nonmedia,send)
        self.assertEqual(sent[0]["status"],413)

    async def test_send_media_body_accepts_exact_transport_limit_and_rejects_one_byte_over(self):
        from telegram_assistant.server import MAX_REQUEST_BYTES
        prefix=(b'{"jsonrpc":"2.0","id":1,"method":"tools/call",'
                b'"params":{"name":"send_media","arguments":{"data_base64":"')
        suffix=b'"}}}'
        def body_of_size(size):
            padding=size-len(prefix)-len(suffix)
            if padding < 0:
                raise AssertionError("test body too small")
            return prefix+b'A'*padding+suffix

        delivered=[]
        async def app(scope,receive,send):
            delivered.append(len((await receive())["body"]))
            await send({"type":"http.response.start","status":200,"headers":[]})
            await send({"type":"http.response.body","body":b'{}'})
        async def call(body):
            events=[]
            async def receive():
                return {"type":"http.request","body":body,"more_body":False}
            async def send(event): events.append(event)
            await RequestLimits(app)({"type":"http","path":"/mcp","method":"POST","headers":[]},receive,send)
            return events

        at_limit=body_of_size(MAX_REQUEST_BYTES)
        accepted=await call(at_limit)
        self.assertEqual(accepted[0]["status"],200)
        self.assertEqual(delivered,[MAX_REQUEST_BYTES])
        at_limit=None
        over_limit=body_of_size(MAX_REQUEST_BYTES+1)
        rejected=await call(over_limit)
        self.assertEqual(rejected[0]["status"],413)
        self.assertEqual(delivered,[MAX_REQUEST_BYTES])

    async def test_no_tracebacks_or_oversize_from_app(self):
        async def broken(scope,receive,send):
            raise RuntimeError("TOKEN_AND_TEXT_SECRET")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=RequestLimits(broken)),base_url="http://test") as http:
            response=await http.post("/mcp",json={"id":1})
            self.assertEqual(response.status_code,503)
            self.assertNotIn("TOKEN_AND_TEXT_SECRET",response.text)
        async def oversized(scope,receive,send):
            await send({"type":"http.response.start","status":200,"headers":[]})
            await send({"type":"http.response.body","body":b"x"*100000})
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=RequestLimits(oversized)),base_url="http://test") as http:
            response=await http.post("/mcp",json={"id":1})
            self.assertEqual(response.status_code,503)
            self.assertLess(len(response.content),100)


class DiagnosticBoundsTests(unittest.TestCase):
    def test_cap_retention_and_cutoff(self):
        now = [1_000_000]
        with tempfile.TemporaryDirectory() as folder:
            diagnostics = Auth401Diagnostics(Path(folder) / "auth-401.sqlite", now[0] + 200_000,
                                              clock=lambda: now[0])
            for _ in range(300):
                diagnostics.record("missing")
            with sqlite3.connect(diagnostics.path) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM auth_401").fetchone()[0], 256)
            now[0] += 86_401
            diagnostics.record("claims")
            with sqlite3.connect(diagnostics.path) as db:
                self.assertEqual(db.execute("SELECT reason FROM auth_401").fetchall(), [("claims",)])
            now[0] = diagnostics.until_epoch
            self.assertIsNone(diagnostics.record("jwks"))
