import unittest
from pty_qr_driver import probe


class QRActualCLITests(unittest.TestCase):
    def test_private_qr_success_and_2fa_stopping(self):
        for mode in ('success','2fa'):
            with self.subTest(mode=mode):
                probe(mode)

    def test_qr_expiry_and_small_terminal(self):
        for mode in ('expired','small'):
            with self.subTest(mode=mode):
                probe(mode)

    def test_cancellation_before_and_after_qr(self):
        for mode in ('consent','cancel'):
            with self.subTest(mode=mode):
                probe(mode)
