"""Independent synthetic SRP server and pinned QR flow, with no network.

SRP equations: https://core.telegram.org/api/srp
Public known Telegram prime: Telethon 1.45.0 check_prime_and_good.
All passwords, salts, sessions and token bytes here are artificial.
"""
import asyncio
import hashlib
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from telethon import errors, functions, password, types
from telethon.client.auth import AuthMethods


PRIME = bytes.fromhex(
    'c71caeb9c6b1c9048e6c522f70f13f73980d40238e3e21c14934d037563d930f'
    '48198a0aa7c14058229493d22530f4dbfa336f6e0ac925139543aed44cce7c37'
    '20fd51f69458705ac68cd4fe6b6b13abdc9746512969328454f18faf8c595f64'
    '2477fe96bb2a941d5bcd1d4ac8cc49880708fa9b378e3c4f3a9060bee67cf9a4'
    'a4a695811051907e162753b56b0f6b410dba74d8a84b2a14b3144e0ef1284754'
    'fd17ed950d5965b4b9dd46582db1178d169c6bc465b0d6ff9ca3928fef5b9ae4'
    'e418fc15e83ebea0f87fa9ff5eed70050ded2849f47bf959d956850ce929851f'
    '0d8115f635b105ee2e4e15d04b2454bf6f4fadf034b10403119cd8e3b92fcc5b'
)


def digest(*parts):
    return hashlib.sha256(b''.join(parts)).digest()


def padded(number):
    return number.to_bytes(256, 'big')


def independent_kdf(value, salt1, salt2):
    first = digest(salt1, value.encode('utf-8'), salt1)
    second = digest(salt2, first, salt2)
    stretched = hashlib.pbkdf2_hmac('sha512', second, salt1, 100000)
    return digest(salt2, stretched, salt2)


class SyntheticSRPServer(unittest.TestCase):
    def test_real_sdk_proof_matches_independent_server(self):
        salt1, salt2 = b'fake-only-first-salt', b'fake-only-second-salt'
        p, g = int.from_bytes(PRIME, 'big'), 3
        b = int.from_bytes(hashlib.shake_256(b'fake-only-server-secret').digest(256), 'big')
        k = int.from_bytes(digest(PRIME, padded(g)), 'big')
        for value in ('  fake spaces  ', 'фиктивный_秘密_🙂', 'fake_Cafe\u0301',
                      'fake_$`\\!@#%&\'"()[]{}'):
            with self.subTest(kind=value[:4]):
                algo = types.PasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow(
                    salt1=salt1, salt2=salt2, g=g, p=PRIME)
                ph = independent_kdf(value, salt1, salt2)
                self.assertEqual(password.compute_hash(algo, value), ph)
                verifier = pow(g, int.from_bytes(ph, 'big'), p)
                B = (k * verifier + pow(g, b, p)) % p
                request = SimpleNamespace(current_algo=algo, srp_B=padded(B), srp_id=123456)
                proof = password.compute_check(request, value)
                A = int.from_bytes(proof.A, 'big')
                u = int.from_bytes(digest(proof.A, padded(B)), 'big')
                S = pow((A * pow(verifier, u, p)) % p, b, p)
                K = digest(padded(S))
                xor = bytes(a ^ b for a, b in zip(digest(PRIME), digest(padded(g))))
                M2 = digest(xor, digest(salt1), digest(salt2), proof.A, padded(B), K)
                self.assertEqual(proof.M1, M2)
                self.assertEqual(proof.srp_id, request.srp_id)
                self.assertEqual(len(proof.A), 256)
                self.assertEqual(len(proof.M1), 32)


class FakeQRClient:
    api_id, api_hash = 12345, 'a' * 32
    def __init__(self, responses):
        self.responses = iter(responses)
        self.handlers, self.calls, self.switched = [], [], []
        self.logged_in = None
    async def __call__(self, request):
        self.calls.append(request)
        response = next(self.responses)
        if isinstance(response, Exception):
            raise response
        return response
    def add_event_handler(self, handler, event):
        self.handlers.append(handler)
    def remove_event_handler(self, handler):
        self.handlers.remove(handler)
    async def _switch_dc(self, dc):
        self.switched.append(dc)
    async def _on_login(self, user):
        self.logged_in = user


def fake_token():
    return types.auth.LoginToken(datetime.now(timezone.utc) + timedelta(seconds=30),
                                 b'fake-only-qr-token')


class PinnedQRFlow(unittest.IsolatedAsyncioTestCase):
    async def start_wait(self, responses):
        client = FakeQRClient([fake_token(), *responses])
        qr = await AuthMethods.qr_login(client)
        self.assertTrue(qr.url.startswith('tg://login?token='))
        task = asyncio.create_task(qr.wait(timeout=1))
        await asyncio.sleep(0)
        self.assertEqual(len(client.handlers), 1)
        await client.handlers[0](types.UpdateLoginToken())
        return client, task

    async def test_success_creates_authorized_session_flow(self):
        user = object()
        success = types.auth.LoginTokenSuccess(SimpleNamespace(user=user))
        client, task = await self.start_wait([success])
        self.assertIs(await task, user)
        self.assertIs(client.logged_in, user)
        self.assertEqual(client.handlers, [])
        self.assertTrue(all(isinstance(c, functions.auth.ExportLoginTokenRequest) for c in client.calls))

    async def test_migration_uses_only_new_qr_token(self):
        user = object()
        success = types.auth.LoginTokenSuccess(SimpleNamespace(user=user))
        client, task = await self.start_wait([types.auth.LoginTokenMigrateTo(4, b'fake-only-migrate'), success])
        self.assertIs(await task, user)
        self.assertEqual(client.switched, [4])
        self.assertIsInstance(client.calls[-1], functions.auth.ImportLoginTokenRequest)

    async def test_password_needed_is_propagated_not_bypassed(self):
        client, task = await self.start_wait([errors.SessionPasswordNeededError(None)])
        with self.assertRaises(errors.SessionPasswordNeededError):
            await task
        self.assertIsNone(client.logged_in)
        self.assertEqual(client.handlers, [])
