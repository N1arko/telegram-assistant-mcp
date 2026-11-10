"""Regression tests use synthetic files only; no Telegram or provider calls."""
import hashlib
import json
import tempfile
import unittest
import zipfile
from io import BytesIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

from telegram_assistant.media import DocumentText, extract_document_text
from telegram_assistant.security import Denied, RateGate
from telegram_assistant.service import MAX_BYTES, SCOPES, Service, wire_size
from test_media import MediaBackend, synthetic_pdf


def synthetic_docx(text):
    xml = ('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:body><w:p><w:r><w:t>' + text + '</w:t></w:r></w:p></w:body></w:document>')
    output = BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('word/document.xml', xml.encode())
    return output.getvalue()


class DocumentWindowTests(unittest.TestCase):
    def check_windows(self, path, expected, *, mime=None):
        # Cross markup/page/Unicode boundaries, exact EOF, and offsets beyond EOF.
        for limit in (1, 2, 7, 6000):
            for offset in (*range(min(len(expected) + 1, 30)), len(expected), len(expected) + 1):
                with self.subTest(limit=limit, offset=offset):
                    result = extract_document_text(path, declared_mime=mime,
                                                   max_chars=limit, text_offset=offset)
                    self.assertEqual(result.text, expected[offset:offset + limit])
                    self.assertEqual(result.truncated, offset + limit < len(expected))

    def test_text_windows_use_unicode_characters(self):
        expected = 'Привет 😀 e\u0301\nСледующая строка'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'document.txt'
            for encoding in ('utf-8-sig', 'utf-16'):
                path.write_bytes(expected.encode(encoding))
                self.check_windows(path, expected, mime='text/plain')

    def test_docx_windows_preserve_tabs_breaks_and_paragraphs(self):
        text = 'Привет 😀</w:t><w:tab/><w:t>ABC</w:t><w:br/><w:t>DEF'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'document.docx'
            path.write_bytes(synthetic_docx(text))
            self.check_windows(path, 'Привет 😀\tABC\nDEF\n')

    def test_pdf_windows_cross_pages_and_empty_pages(self):
        module = ModuleType('pypdf')
        page_texts = ['First 😀', '', 'Final page']
        module.PdfReader = lambda *args, **kwargs: SimpleNamespace(
            is_encrypted=False,
            pages=[SimpleNamespace(extract_text=lambda text=text: text) for text in page_texts])
        expected = ''.join(text + '\n\n' for text in page_texts)
        with tempfile.TemporaryDirectory() as folder, patch.dict('sys.modules', {'pypdf': module}):
            path = Path(folder) / 'document.pdf'
            path.write_bytes(b'%PDF-1.4\nsynthetic')
            self.check_windows(path, expected)

    def test_helper_rejects_invalid_window_before_opening_file(self):
        for options in ({'text_offset': -1}, {'text_offset': True}, {'text_offset': 2**31},
                        {'max_chars': 0}, {'max_chars': 6001}, {'max_chars': False}):
            with self.subTest(options=options), self.assertRaises(Denied) as error:
                extract_document_text(Path('nonexistent'), **options)
            self.assertEqual(error.exception.code, 'invalid_argument')


class DocumentPaginationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scope = SCOPES.set(frozenset({'telegram:read'}))

    async def asyncTearDown(self):
        SCOPES.reset(self.scope)

    async def read_all(self, raw, expected, mime, *, limit=6000):
        backend = MediaBackend(raw, {'declared_mime': mime})
        service = Service(backend, gate=RateGate(limit=100))
        digest = hashlib.sha256(raw).hexdigest()
        pieces, offset = [], 0
        while True:
            result = await service.invoke('read_document', peer_id=42, message_id=7,
                                          text_offset=offset, text_limit=limit,
                                          expected_document_sha256=digest)
            self.assertNotIn('error', result)
            self.assertEqual(result['document_sha256'], digest)
            self.assertEqual(result['text_offset'], offset)
            self.assertEqual(result['text'], expected[offset:offset + len(result['text'])])
            self.assertLessEqual(wire_size(result), MAX_BYTES)
            self.assertLessEqual(len(result['text']), limit)
            self.assertTrue(result['untrusted_content'])
            pieces.append(result['text'])
            next_offset = result['text_next_offset']
            self.assertEqual(result['text_truncated'], next_offset is not None)
            self.assertEqual(result['text_complete'], offset == 0 and next_offset is None)
            if next_offset is None:
                break
            self.assertEqual(next_offset, offset + len(result['text']))
            self.assertGreater(next_offset, offset)
            offset = next_offset
            self.assertLessEqual(len(pieces), len(expected) + 1)
        self.assertEqual(''.join(pieces), expected)
        return backend, service

    async def test_entire_long_unicode_plain_text(self):
        text = ('Пример 😀 e\u0301\n' * 1500) + 'unique final marker'
        await self.read_all(text.encode(), text, 'text/plain')

    async def test_entire_long_docx(self):
        text = 'Document 😀 text ' * 1200
        await self.read_all(synthetic_docx(text), text + '\n',
                            'application/vnd.openxmlformats-officedocument.wordprocessingml.document')

    async def test_entire_long_pdf_through_real_local_worker(self):
        text = 'synthetic page content ' * 600
        await self.read_all(synthetic_pdf(text), text + '\n\n', 'application/pdf')

    async def test_exact_chunk_boundaries_do_not_create_phantom_next_page(self):
        for size in (1, 6000, 12000):
            with self.subTest(size=size):
                text = 'x' * size
                await self.read_all(text.encode(), text, 'text/plain')
                await self.read_all(synthetic_docx(text[:-1]), text[:-1] + '\n',
                                    'application/vnd.openxmlformats-officedocument.wordprocessingml.document')

    async def test_custom_limit_and_empty_text_at_end(self):
        _, service = await self.read_all(b'abcdef', 'abcdef', 'text/plain', limit=2)
        for offset in (6, 7):
            result = await service.invoke('read_document', peer_id=42, message_id=7, text_offset=offset)
            self.assertEqual(result['text'], '')
            self.assertIsNone(result['text_next_offset'])
            self.assertFalse(result['text_truncated'])
            self.assertFalse(result['text_complete'])

    async def test_whitespace_only_document_still_has_continuation(self):
        await self.read_all(b' ' * 7000, ' ' * 7000, 'text/plain')

    async def test_scan_pdf_returns_no_text_without_claiming_ocr(self):
        backend = MediaBackend(synthetic_pdf(''), {'declared_mime': 'application/pdf'})
        service = Service(backend)
        result = await service.invoke('read_document', peer_id=42, message_id=7)
        self.assertFalse(result['text_available'])
        self.assertTrue(result['text_complete'])
        self.assertIsNone(result['text_next_offset'])

    async def test_document_hash_prevents_mixed_revisions(self):
        backend = MediaBackend(b'original document', {'declared_mime': 'text/plain'})
        service = Service(backend)
        first = await service.invoke('read_document', peer_id=42, message_id=7, text_limit=4)
        backend.media_bytes = b'replacement document'
        with patch('telegram_assistant.service.extract_document_text') as extract:
            result = await service.invoke('read_document', peer_id=42, message_id=7,
                                          text_offset=first['text_next_offset'],
                                          expected_document_sha256=first['document_sha256'])
        self.assertEqual(result, {'error': 'document_changed'})
        extract.assert_not_called()

    async def test_invalid_arguments_never_resolve_or_download(self):
        backend = MediaBackend(b'text', {'declared_mime': 'text/plain'})
        service = Service(backend)
        for options in ({'text_offset': True}, {'text_offset': -1}, {'text_offset': 1.5},
                        {'text_offset': 2**31}, {'text_limit': False}, {'text_limit': 0},
                        {'text_limit': 6001}, {'text_limit': '3'},
                        {'expected_document_sha256': 'z' * 64},
                        {'expected_document_sha256': 'a' * 63},
                        {'expected_document_sha256': []}):
            with self.subTest(options=options):
                result = await service.invoke('read_document', peer_id=42, message_id=7, **options)
                self.assertEqual(result, {'error': 'invalid_argument'})
        backend.resolve.assert_not_awaited()
        self.assertEqual(backend.fetch_calls, 0)

    async def test_continuation_preserves_read_scope_and_recipient_checks(self):
        backend = MediaBackend(b'synthetic', {'declared_mime': 'text/plain'})
        service = Service(backend)
        token = SCOPES.set(frozenset())
        try:
            result = await service.invoke('read_document', peer_id=42, message_id=7, text_offset=6000)
        finally:
            SCOPES.reset(token)
        self.assertEqual(result, {'error': 'unauthorized'})
        backend.resolve.assert_not_awaited()
        backend.resolve.side_effect = Denied('peer_not_allowed')
        result = await service.invoke('read_document', peer_id=42, message_id=7, text_offset=6000)
        self.assertEqual(result, {'error': 'peer_not_allowed'})
        self.assertEqual(backend.fetch_calls, 0)

    async def test_wire_size_shortening_does_not_skip_text(self):
        # Force a smaller envelope budget to exercise adaptive page shortening.
        text = '\\"😀' * 2100
        with patch('telegram_assistant.service.MAX_BYTES', 900):
            backend, _ = await self.read_all(text.encode(), text, 'text/plain')
        self.assertGreater(backend.fetch_calls, 2)

    async def test_worker_rejects_invalid_or_nonprogressing_page(self):
        for output in ({'text': '', 'truncated': True, 'pages': 1},
                       {'text': 'x' * 11, 'truncated': False, 'pages': 1},
                       {'text': 'x', 'truncated': False, 'pages': 101},
                       {'text': 'x', 'truncated': 1, 'pages': 1}):
            with self.subTest(output=output), patch('telegram_assistant.service._run_bounded',
                    AsyncMock(return_value=json.dumps(output).encode())):
                with self.assertRaises(Denied) as error:
                    await Service._extract_pdf_in_worker(Path('synthetic.pdf'), text_limit=10)
                self.assertEqual(error.exception.code, 'document_parse_failed')

    async def test_temporary_file_removed_after_success_and_changed_error(self):
        paths = []
        backend = MediaBackend(b'synthetic', {'declared_mime': 'text/plain'})
        fetch = backend.fetch_media_file
        async def track(*args, **kwargs):
            paths.append(kwargs['destination'])
            return await fetch(*args, **kwargs)
        backend.fetch_media_file = track
        service = Service(backend)
        await service.invoke('read_document', peer_id=42, message_id=7)
        await service.invoke('read_document', peer_id=42, message_id=7,
                             expected_document_sha256='0' * 64)
        self.assertEqual(len(paths), 2)
        self.assertTrue(all(not path.exists() for path in paths))
