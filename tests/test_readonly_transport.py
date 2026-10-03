import unittest
import test_auth_transport as base


class ReadOnlyTransportTests(unittest.IsolatedAsyncioTestCase):
    read_only = True
    asyncSetUp = base.TransportTests.asyncSetUp
    asyncTearDown = base.TransportTests.asyncTearDown
    rpc = base.TransportTests.rpc

    async def test_metadata_registry_and_owner_initialize(self):
        response = await self.http.get('/.well-known/oauth-protected-resource/mcp')
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.json()['scopes_supported'],['telegram:read'])
        response = await self.rpc('initialize',{'protocolVersion':'2025-06-18',
            'capabilities':{},'clientInfo':{'name':'mock-owner','version':'1'}})
        self.assertEqual(response.status_code,200)
        response = await self.rpc('tools/list')
        tools = response.json()['result']['tools']
        self.assertEqual({t['name'] for t in tools},
            {'list_dialogs','get_history','search_messages','get_reply_context','view_photo','transcribe_audio'})
        self.assertTrue(all(t['annotations']['readOnlyHint'] for t in tools))

    async def test_send_absent_even_for_valid_owner_with_write_scope(self):
        response = await self.rpc('tools/call',{'name':'send_message',
            'arguments':{'peer_id':42,'text':'fake-only'}},token='fake-write')
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.json()['result']['isError'])
        self.fake.send.assert_not_awaited()

    async def test_no_token_invalid_and_wrong_owner_never_reach_backend(self):
        for token in [None,'invalid',base.signed(base.claims(sub='other-owner'))]:
            response = await self.rpc('tools/call',{'name':'get_history',
                'arguments':{'peer_id':42,'limit':1}},token=token)
            self.assertEqual(response.status_code,401)
            self.assertIn('resource_metadata',response.headers['www-authenticate'])
        self.fake.history.assert_not_awaited()
