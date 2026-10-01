import unittest

from pty_login_driver import command_for, run_pty


class TerminalLoginTests(unittest.TestCase):
    def assert_private_mock_success(self, status, transcript):
        self.assertEqual(status, 0, transcript)
        self.assertIn(b"MOCK_CODE_REQUEST", transcript)
        self.assertIn(b"TTY_FLAGS_RESTORED", transcript)
        self.assertNotIn(b"a" * 32, transcript)
        self.assertNotIn(b"+15555550100", transcript)
        self.assertNotIn(b"12345", transcript)

    def test_full_pty_flow_lf_cr_crlf_and_paste(self):
        for suffix, confirmation in (
            (b"\n", b"SEND"), (b"\r", b"SEND"), (b"\r\n", b"SEND"),
            (b"\n", b"\x1b[200~SEND\x1b[201~"),
        ):
            with self.subTest(suffix=suffix, paste=confirmation != b"SEND"):
                status, transcript = run_pty(command_for(), suffix=suffix,
                                             confirmation=confirmation, preflight=True)
                self.assert_private_mock_success(status, transcript)

    def test_pty_retry_preflight_and_send_keep_fields_private(self):
        status, transcript = run_pty(
            command_for(), preflight=True,
            preflight_answers=(b"", "CHЕCK".encode(), b"CHECK"),
            confirmation=(b"", "SЕND".encode(), b"SEND"),
        )
        self.assert_private_mock_success(status, transcript)
        self.assertEqual(transcript.count(b"API ID (hidden): "), 1)
        self.assertEqual(transcript.count(b"API hash (hidden): "), 1)
        self.assertIn(b"empty_line", transcript)
        self.assertIn(b"non_ascii", transcript)

    def test_pty_explicit_cancellation_never_connects(self):
        status, transcript = run_pty(command_for(), preflight=True, confirmation=b"CANCEL")
        self.assertEqual(status, 1, transcript)
        self.assertNotIn(b"MOCK_CONNECT", transcript)
        self.assertIn(b"TTY_FLAGS_RESTORED", transcript)

    def test_utf8_character_erased_before_ascii_word_and_hidden_fields(self):
        edited = "С".encode() + b"\x7f"
        status, transcript = run_pty(
            command_for(), preflight=True, preflight_answers=(edited + b"CHECK",),
            confirmation=edited + b"SEND", field_prefix=edited,
        )
        self.assert_private_mock_success(status, transcript)
        self.assertNotIn(b"terminal_encoding_error", transcript)

    def test_invalid_utf8_retries_confirmation_and_current_secret_field(self):
        status, transcript = run_pty(
            command_for(), preflight=True, preflight_answers=(b"\xffCHECK", b"CHECK"),
            confirmation=(b"\xffSEND", b"SEND"),
            field_answers={b"API ID (hidden): ": (b"\xff12345", b"12345")},
        )
        self.assert_private_mock_success(status, transcript)
        self.assertIn(b"invalid_utf8", transcript)
        self.assertIn(b"Invalid UTF-8 input; re-enter this field.", transcript)
        self.assertEqual(transcript.count(b"API hash (hidden): "), 1)

    def test_corrupted_check_never_accepts_until_correct_confirmation(self):
        status, transcript = run_pty(
            command_for(), preflight=True, preflight_answers=(b"\xffCHECK", b"CANCEL"),
        )
        self.assertEqual(status, 1, transcript)
        self.assertNotIn(b"API ID (hidden): ", transcript)
        self.assertNotIn(b"MOCK_CONNECT", transcript)
        self.assertIn(b"invalid_utf8", transcript)
