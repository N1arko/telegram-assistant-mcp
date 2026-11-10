"""Preserve deployed metadata diagnostics without recording message contents."""
import json
import os
import stat
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from telegram_assistant import diagnostics


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.token = diagnostics.state.set({"stage": "operation"})
        self.backend = SimpleNamespace(client=SimpleNamespace(is_connected=lambda: True))

    def tearDown(self):
        diagnostics.state.reset(self.token)

    def test_stage_and_record_keep_only_fixed_metadata(self):
        diagnostics.stage("history")
        with patch.object(diagnostics, "expires", float("inf")), \
             patch.object(diagnostics.os, "open", return_value=123) as opened, \
             patch.object(diagnostics.os, "fstat", return_value=SimpleNamespace(
                 st_mode=stat.S_IFREG | 0o600, st_uid=os.geteuid(), st_size=0)), \
             patch.object(diagnostics.os, "write") as written, \
             patch.object(diagnostics.os, "close") as closed:
            diagnostics.record("read_document", self.backend, "exception",
                               ValueError("synthetic private document body"))
        row = json.loads(written.call_args.args[1])
        self.assertEqual(set(row), {"time_utc", "operation", "stage", "outcome",
                                   "exception_class", "connected"})
        self.assertEqual(row["stage"], "history")
        self.assertEqual(row["exception_class"], "ValueError")
        self.assertNotIn(b"synthetic private", written.call_args.args[1])
        self.assertTrue(opened.call_args.args[1] & os.O_NOFOLLOW)
        self.assertEqual(opened.call_args.args[2], 0o600)
        closed.assert_called_once_with(123)

    def test_expired_diagnostics_do_not_open_file(self):
        with patch.object(diagnostics, "expires", 0), patch.object(diagnostics.os, "open") as opened:
            diagnostics.record("read_document", self.backend, "success")
        opened.assert_not_called()

    def test_nonregular_wrong_owner_and_full_files_are_not_written(self):
        for mode, uid, size in ((stat.S_IFDIR, os.geteuid(), 0),
                                (stat.S_IFREG, os.geteuid() + 1, 0),
                                (stat.S_IFREG, os.geteuid(), 131072)):
            with self.subTest(mode=mode, uid=uid, size=size), \
                 patch.object(diagnostics, "expires", float("inf")), \
                 patch.object(diagnostics.os, "open", return_value=123), \
                 patch.object(diagnostics.os, "fstat", return_value=SimpleNamespace(
                     st_mode=mode, st_uid=uid, st_size=size)), \
                 patch.object(diagnostics.os, "write") as written, \
                 patch.object(diagnostics.os, "close"):
                diagnostics.record("read_document", self.backend, "success")
                written.assert_not_called()

    def test_diagnostic_failure_does_not_break_operation(self):
        with patch.object(diagnostics, "expires", float("inf")), \
             patch.object(diagnostics.os, "open", side_effect=OSError):
            diagnostics.record("read_document", self.backend, "success")
