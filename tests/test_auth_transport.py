import json
import asyncio
import time
import unittest
from unittest.mock import AsyncMock

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
import httpx
from telegram_assistant.auth import AuthConfig, JWKSVerifier, validate_claims
from telegram_assistant.server import RequestLimits, build_app, build_mcp
from telegram_assistant.service import Service
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
        self.mcp=build_mcp(Service(self.fake),CONFIG,self.verifier,read_only=getattr(self,"read_only",False))
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
            ("tools/list",{}),("tools/call",{"name":"get_history","arguments":{"peer_id":42}})]:
            for token in [None,"invalid"]:
                response=await self.rpc(method,params,token=token)
                self.assertEqual(response.status_code,401,response.text)
                self.assertIn("resource_metadata",response.headers["www-authenticate"])
        self.fake.history.assert_not_awaited()
        self.fake.send.assert_not_awaited()
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
        self.assertEqual(names,{"list_dialogs","get_history","search_messages","get_reply_context","send_message"})
        for name in ["set_policy","edit_message","delete_message","mark_as_read","download_media","transcribe_voice"]:
            result=await self.rpc("tools/call",{"name":name,"arguments":{}})
            self.assertTrue(result.json()["result"]["isError"])
        self.assertEqual(await self.mcp.list_resources(),[])
        self.assertEqual(await self.mcp.list_prompts(),[])
    async def test_history_over_actual_sdk_no_ports(self):
        response=await self.rpc("tools/call",{"name":"get_history","arguments":{"peer_id":42,"limit":3}})
        self.assertEqual(response.status_code,200,response.text)
        payload=json.loads(response.json()["result"]["content"][0]["text"])
        self.assertEqual([m["message_id"] for m in payload["messages"]],[12,11,10])
        self.fake.history.assert_awaited_once()
        self.fake.read_receipt.assert_not_awaited()
    async def test_scope_and_policy_deny(self):
        for token,code in [("fake-read","send_scope_required"),("fake-write","send_denied")]:
            response=await self.rpc("tools/call",{"name":"send_message","arguments":{"peer_id":42,"text":"test"}},token=token)
            self.assertEqual(json.loads(response.json()["result"]["content"][0]["text"])["error"],code)
        self.fake.send.assert_not_awaited()
        self.assertEqual(self.jwks_calls,1)  # Public-key cache; signatures/claims checked each request.
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
