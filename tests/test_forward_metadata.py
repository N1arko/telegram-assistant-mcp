import unittest
from datetime import datetime, timezone
from types import SimpleNamespace as NS
from telethon.tl.types import MessageFwdHeader, PeerUser, PeerChannel
from telegram_assistant.backend import TelethonBackend
from telegram_assistant.service import Service

class ForwardMetadataTests(unittest.TestCase):
    def record(self, header=None):
        msg = NS(id=7, message='example', date=None, sender_id=99, media=None,
                 fwd_from=header)
        return Service._record(TelethonBackend.record(msg), 99)

    def test_ordinary_and_old_cached_records(self):
        row = self.record()
        self.assertFalse(row['is_forwarded'])
        self.assertIsNone(row['forward_origin'])
        old = Service._record({'id': 1, 'text': ''}, 99)
        self.assertFalse(old['is_forwarded'])

    def test_forwarded_user_preserves_sender(self):
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        row = self.record(MessageFwdHeader(date=dt, from_id=PeerUser(12)))
        self.assertTrue(row['is_forwarded'])
        self.assertEqual(row['sender_id'], 99)
        self.assertEqual(row['forward_origin']['peer_id'], 12)
        self.assertEqual(row['forward_origin']['date'], dt.isoformat())
        self.assertIsNone(row['forward_origin']['name'])

    def test_hidden_author_and_bounded_names(self):
        row = self.record(MessageFwdHeader(date=None, from_name='x' * 400))
        self.assertTrue(row['is_forwarded'])
        origin = row['forward_origin']
        self.assertIsNone(origin['peer_id'])
        self.assertEqual(len(origin['name']), 200)
        self.assertTrue(origin['name_truncated'])

    def test_channel_and_signature(self):
        row = self.record(MessageFwdHeader(date=None, from_id=PeerChannel(12),
                       channel_post=5, post_author='editor'))
        origin = row['forward_origin']
        self.assertEqual(origin['peer_id'], -1000000000012)
        self.assertEqual(origin['channel_post'], 5)
        self.assertEqual(origin['post_author'], 'editor')

    def test_empty_header_still_forwarded(self):
        self.assertTrue(self.record(MessageFwdHeader(date=None))['is_forwarded'])

    def test_no_saved_origin_or_other_fields_leak(self):
        row = Service._record({'id': 1, 'text': '', 'is_forwarded': True,
            'forward_origin': {'name': 'example', 'secret': 'do not return',
                               'saved_from_peer': 123}}, 99, exact_text_offset=0)
        self.assertNotIn('secret', row['forward_origin'])
        self.assertNotIn('saved_from_peer', row['forward_origin'])
        self.assertTrue(row['text_complete'])
