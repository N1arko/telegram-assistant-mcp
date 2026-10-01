import getpass
import warnings
import unittest
from unittest.mock import patch
from pty_std_getpass_audit import probe


class StockGetpassAudit(unittest.TestCase):
    def test_standard_reader_and_real_sdk_exact_hidden_input(self):
        for value in ('fake_$`\\!@#%&\'"()[]{}','  fake spaced pass  ',
                      'фиктивный_秘密_🙂','fake_Cafe\u0301'):
            with self.subTest(kind=value[:4]):
                probe(value)

    def test_warning_error_prevents_echoing_fallback(self):
        with warnings.catch_warnings():
            warnings.simplefilter('error',getpass.GetPassWarning)
            with patch('getpass._raw_input',side_effect=AssertionError('must not read echoing input')):
                with self.assertRaises(getpass.GetPassWarning):
                    getpass.fallback_getpass('fake hidden prompt: ')
