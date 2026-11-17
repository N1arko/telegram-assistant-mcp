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
        {'list_dialogs','scan_updates','get_history','search_messages','get_reply_context',
         'list_forum_topics','get_forum_topic','view_photo','get_audio','read_document','download_attachment',
         'transcribe_audio'})
        self.assertNotIn('read_channel', {t['name'] for t in tools})
        self.assertNotIn('list_public_channels', {t['name'] for t in tools})
        self.assertTrue(all(t['annotations']['readOnlyHint'] for t in tools))

    async def test_both_send_tools_absent_even_for_valid_owner_with_write_scope(self):
        response = await self.rpc('tools/call',{'name':'send_message',
            'arguments':{'peer_id':42,'text':'fake-only'}},token='fake-write')
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.json()['result']['isError'])
        response = await self.rpc('tools/call',{'name':'send_media',
            'arguments':{'peer_id':42,'items':[{'media_type':'document','data_base64':'eA=='}]}},token='fake-write')
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.json()['result']['isError'])
        self.fake.send.assert_not_awaited()
        self.fake.send_media_files.assert_not_awaited()

    async def test_no_token_invalid_and_wrong_owner_never_reach_backend(self):
        for token in [None,'invalid',base.signed(base.claims(sub='other-owner'))]:
            response = await self.rpc('tools/call',{'name':'get_history',
                'arguments':{'peer_id':42,'limit':1}},token=token)
            self.assertEqual(response.status_code,401)
            self.assertIn('resource_metadata',response.headers['www-authenticate'])
        self.fake.history.assert_not_awaited()


class OptInTargetedChannelReadTests(unittest.IsolatedAsyncioTestCase):
    read_only = True
    targeted_channel_reads_enabled = True
    asyncSetUp = base.TransportTests.asyncSetUp
    asyncTearDown = base.TransportTests.asyncTearDown
    rpc = base.TransportTests.rpc

    async def test_channel_tool_is_registered_only_when_gate_is_enabled(self):
        response = await self.rpc('tools/list')
        tools = response.json()['result']['tools']
        entry = next(tool for tool in tools if tool['name'] == 'read_channel')
        self.assertTrue(entry['annotations']['readOnlyHint'])
        self.assertIn('text_offset', entry['inputSchema']['properties'])
        listing = next(tool for tool in tools if tool['name'] == 'list_public_channels')
        self.assertTrue(listing['annotations']['readOnlyHint'])
        self.assertEqual(listing.get('_meta'), entry.get('_meta'))
        self.assertEqual(listing['_meta']['securitySchemes'],
                         [{'type': 'oauth2', 'scopes': ['telegram:read']}])
        self.assertNotIn('send_message', {tool['name'] for tool in tools})
        self.assertNotIn('send_media', {tool['name'] for tool in tools})
        self.assertEqual({tool['name'] for tool in tools} &
                         {'read_channel', 'list_public_channels'},
                         {'read_channel', 'list_public_channels'})


class OptInTargetedChannelWriteTransportTests(unittest.IsolatedAsyncioTestCase):
    targeted_channel_reads_enabled = True
    asyncSetUp = base.TransportTests.asyncSetUp
    asyncTearDown = base.TransportTests.asyncTearDown
    rpc = base.TransportTests.rpc

    async def test_gate_adds_only_read_tools_and_keeps_existing_write_scopes(self):
        metadata = await self.http.get('/.well-known/oauth-protected-resource/mcp')
        self.assertEqual(metadata.json()['scopes_supported'], ['telegram:read', 'telegram:send'])
        response = await self.rpc('tools/list')
        tools = response.json()['result']['tools']
        names = {tool['name'] for tool in tools}
        self.assertEqual(names, {
            'list_dialogs', 'get_history', 'search_messages', 'get_reply_context',
            'list_forum_topics', 'get_forum_topic', 'scan_updates', 'view_photo', 'download_attachment',
            'get_audio', 'read_document', 'transcribe_audio', 'send_message', 'send_media',
            'read_channel', 'list_public_channels',
        })
        listing = next(tool for tool in tools if tool['name'] == 'list_public_channels')
        history = next(tool for tool in tools if tool['name'] == 'get_history')
        self.assertTrue(listing['annotations']['readOnlyHint'])
        self.assertEqual(listing['_meta'], history['_meta'])
        send_tools = {tool['name']: tool for tool in tools
                      if tool['name'] in {'send_message', 'send_media'}}
        self.assertEqual(set(send_tools), {'send_message', 'send_media'})
        self.assertTrue(all(tool['_meta']['securitySchemes'][0]['scopes'] ==
                            ['telegram:read', 'telegram:send'] for tool in send_tools.values()))
