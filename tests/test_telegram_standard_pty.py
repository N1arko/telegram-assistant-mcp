import asyncio
import getpass
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from pty_standard_login_driver import probe
from telegram_assistant.telegram_login import LoginSetupError
from telegram_assistant.telegram_standard_login import _run, _stock_secret, ProbeState


class StandardPTYTests(unittest.TestCase):
    def test_actual_standard_cli_success_and_failure_paths(self):
        for mode in ('2fa','no2fa','password_invalid','code_invalid','migration','flood','auth_restart','cancel'):
            with self.subTest(mode=mode):
                probe(mode)

    def test_no_tty_blocks_before_private_reads_or_network(self):
        with patch('sys.stdin.isatty',return_value=False), patch(
                'telegram_assistant.telegram_standard_login.provision_standard_session',
                side_effect=AssertionError('must not read private settings')):
            with self.assertRaises(LoginSetupError) as raised:
                asyncio.run(_run(SimpleNamespace(),ProbeState()))
        self.assertEqual(raised.exception.code,'interactive_tty_required')

    def test_production_reader_aborts_before_echoing_fallback(self):
        with patch('telegram_assistant.telegram_standard_login.getpass.getpass',
                side_effect=getpass.fallback_getpass), patch('getpass._raw_input',
                side_effect=AssertionError('must not read echoing input')):
            with self.assertRaises(LoginSetupError) as raised:
                _stock_secret('synthetic hidden field: ')
        self.assertEqual(raised.exception.code,'standard_terminal_input_failed')
