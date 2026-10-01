import unittest
from types import SimpleNamespace
from unittest.mock import patch

from telethon import functions, types
from telethon.client.auth import AuthMethods

from telegram_assistant.telegram_login import LoginSetupError, _secret_terminal_framing
from pty_password_driver import CASES, probe


class PasswordTransportTests(unittest.TestCase):
    def test_framing_preserves_whitespace_unicode_and_specials(self):
        for value in ("  fake spaces  ", "фиктивный_秘密_🙂", "fake_Cafe\u0301",
                      "fake_$`\\!@#%&'\"()[]{}", ""):
            with self.subTest(value=value):
                self.assertEqual(_secret_terminal_framing(value), value)
                self.assertEqual(_secret_terminal_framing("\x1b[200~" + value + "\x1b[201~"), value)

    def test_partial_nested_or_other_escape_framing_is_rejected(self):
        for value in ("\x1b[200~fake", "fake\x1b[201~", "fake\x1b[A",
                      "\x1b[200~\x1b[200~fake\x1b[201~\x1b[201~"):
            with self.subTest(value=value), self.assertRaises(LoginSetupError) as raised:
                _secret_terminal_framing(value)
            self.assertEqual(raised.exception.code, "terminal_paste_framing_error")

    def test_full_cli_preserves_password_exactly_all_input_cases(self):
        for case in CASES:
            with self.subTest(case=case[0]):
                exact, output = probe(case)
                self.assertTrue(exact)
                self.assertIn(b"PASTE_FRAMING_REACHED_CLIENT=False", output)

    def test_full_cli_retries_only_password_after_partial_or_multiline_paste(self):
        case = ("partial-paste-retry", "fake_after_retry", None)
        for bad in (b"\x1b[200~fake_partial", b"fake_partial\x1b[201~",
                    b"\x1b[200~fake_line1\nfake_line2\x1b[201~"):
            with self.subTest(kind=bad[:6]):
                exact, output = probe(case, answers=(bad, b"fake_after_retry"))
                self.assertTrue(exact)
                self.assertIn(b"Incomplete or unsupported terminal paste", output)
                self.assertEqual(output.count(b"Type SEND (or CANCEL): "), 1)
                self.assertEqual(output.count(b"Telegram login code (hidden): "), 1)

    def test_invalid_utf8_password_retries_without_discarding_bytes(self):
        exact, output = probe(("invalid-utf8-password", "fake_utf8_retry", None),
                              answers=(b"\xfffake_utf8_retry", b"fake_utf8_retry"))
        self.assertTrue(exact)
        self.assertIn(b"Invalid UTF-8 input; re-enter this field.", output)
        self.assertEqual(output.count(b"Type SEND (or CANCEL): "), 1)


class PinnedTelethonPasswordTests(unittest.IsolatedAsyncioTestCase):
    async def test_sign_in_passes_exact_password_to_srp_without_network(self):
        password_request = object()
        user = object()
        class FakeRPCClient:
            async def get_me(self):
                return None
            async def __call__(self, request):
                if isinstance(request, functions.account.GetPasswordRequest):
                    return password_request
                if isinstance(request, functions.auth.CheckPasswordRequest):
                    return SimpleNamespace(user=user)
                raise AssertionError("unexpected RPC type")
            async def _on_login(self, actual):
                return actual
        for value in ("  fake spaces  ", "фиктивный_秘密_🙂", "fake_Cafe\u0301",
                      "fake_$`\\!@#%&'\"()[]{}"):
            with self.subTest(kind=value[:4]), patch('telethon.password.compute_check',
                    return_value=types.InputCheckPasswordEmpty()) as srp:
                self.assertIs(await AuthMethods.sign_in(FakeRPCClient(), password=value), user)
                srp.assert_called_once_with(password_request, value)
