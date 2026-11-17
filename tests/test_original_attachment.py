import base64
import hashlib
import json
import unittest
from unittest.mock import AsyncMock
from telegram_assistant.service import Service, SCOPES
from telegram_assistant.security import Denied

class Backend:
    def __init__(self, data):
        self.data = data
        self.resolve = AsyncMock(return_value=(42, 'user'))
        self.paths = []
    async def fetch_media_file(self, target, message_id, *, kind, destination, max_bytes):
        assert kind == 'original'
        if len(self.data) > max_bytes:
            raise Denied('media_too_large')
        self.paths.append(destination)
        destination.write_bytes(self.data)
        return {'kind': 'document'}

class OriginalTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.token = SCOPES.set(frozenset({'telegram:read'}))
    async def asyncTearDown(self):
        SCOPES.reset(self.token)
    async def test_exact_chunks_and_cleanup(self):
        data = bytes(range(256)) * 201
        backend = Backend(data)
        service = Service(backend)
        result = bytearray(); offset = 0; digest = None
        while True:
            response = await service.invoke('download_attachment', peer_id=42,
                message_id=9, offset=offset, expected_sha256=digest)
            self.assertLess(len(json.dumps(response)), 48*1024)
            result.extend(base64.b64decode(response['data_base64']))
            digest = response['sha256']; offset = response['next_offset']
            if offset is None: break
        self.assertEqual(bytes(result), data)
        self.assertEqual(digest, hashlib.sha256(data).hexdigest())
        self.assertTrue(all(not p.exists() for p in backend.paths))
    async def test_scope_and_membership_fail_closed(self):
        backend = Backend(b'data'); service = Service(backend)
        SCOPES.set(frozenset())
        self.assertEqual(await service.invoke('download_attachment',peer_id=42,message_id=9), {'error':'unauthorized'})
        backend.resolve.assert_not_awaited()
        SCOPES.set(frozenset({'telegram:read'}))
        backend.resolve.side_effect = Denied('peer_not_allowed')
        self.assertEqual(await service.invoke('download_attachment',peer_id=42,message_id=9), {'error':'peer_not_allowed'})
        self.assertEqual(backend.paths, [])
    async def test_changed_offset_and_size(self):
        backend = Backend(b'data'); service = Service(backend)
        for kwargs, error in [({'offset':1}, 'attachment_hash_required'),
            ({'expected_sha256':'0'*64}, 'attachment_changed'),
            ({'offset':4,'expected_sha256':hashlib.sha256(b'data').hexdigest()}, 'invalid_attachment_offset'),
            ({'offset':True}, 'invalid_argument')]:
            result = await service.invoke('download_attachment',peer_id=42,message_id=9,**kwargs)
            self.assertEqual(result['error'],error)
        backend.data = b'x' * (8*1024*1024+1)
        self.assertEqual((await service.invoke('download_attachment',peer_id=42,message_id=9))['error'], 'media_too_large')
        self.assertTrue(all(not p.exists() for p in backend.paths))

class BackendOriginalTests(unittest.IsolatedAsyncioTestCase):
    async def test_photo_document_bytes_are_not_reencoded(self):
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace as NS
        from telegram_assistant.backend import TelethonBackend
        data=b'original-image-document-bytes'
        document=NS(size=len(data), mime_type='image/png', attributes=[])
        message=NS(id=7, document=document, photo=None, media=document)
        backend=TelethonBackend.__new__(TelethonBackend)
        backend.activate=AsyncMock(); backend.peers={42:object()}
        async def chunks(*args, **kwargs):
            yield data
        backend.client=NS(get_messages=AsyncMock(return_value=message),iter_download=chunks)
        with tempfile.TemporaryDirectory() as directory:
            dest=Path(directory)/'original'
            result=await backend.fetch_media_file(42,7,kind='original',destination=dest,max_bytes=100)
            self.assertEqual(dest.read_bytes(),data)
            self.assertEqual(dest.stat().st_mode & 0o777,0o600)
            self.assertEqual(result['size'],len(data))
