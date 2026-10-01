import asyncio
import base64
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from telethon.crypto.authkey import AuthKey
from telethon.errors import SessionPasswordNeededError, FloodWaitError, RPCError
from telethon.sessions import SQLiteSession

from telegram_assistant.telegram_login import LoginSetupError, _save_private_config
from telegram_assistant.telegram_qr_login import provision_qr_session, _provision_lock

FAKE_KEY = b'fake-only-auth-key-' * 14 + b'pad!'
FAKE_URI = 'tg://login?token=' + base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
PHONE = '+15555550100'


class FakeQR:
    url = FAKE_URI
    def __init__(self, client, *, error=None, phone=PHONE[1:], expiry=30, user_id=123456):
        self.client, self.error = client, error
        self.phone, self.user_id = phone, user_id
        self.expires = datetime.now(timezone.utc) + timedelta(seconds=expiry)
        self.started, self.approved = asyncio.Event(), asyncio.Event()
        self.timeout = None
    async def wait(self, timeout):
        self.timeout = timeout
        self.started.set()
        await asyncio.wait_for(self.approved.wait(), timeout)
        if self.error is not None:
            raise self.error
        self.client.authorized = True
        self.client.session.auth_key = AuthKey(FAKE_KEY)
        return SimpleNamespace(id=self.user_id, phone=self.phone, bot=False)


class FakeClient:
    def __init__(self, path, api_id, api_hash, **kwargs):
        assert api_id == 12345 and api_hash == 'a' * 32
        self.session = SQLiteSession(path)
        self.authorized, self.exports, self.disconnects = False, 0, 0
        self.kwargs = kwargs
        self.qr = FakeQR(self)
    async def connect(self):
        pass
    async def is_user_authorized(self):
        return self.authorized
    async def qr_login(self):
        self.exports += 1
        return self.qr
    async def disconnect(self):
        self.disconnects += 1
        self.session.close()
    async def send_code_request(self, *_args):
        raise AssertionError('QR must never request phone code')
    async def sign_in(self, **_kwargs):
        raise AssertionError('QR must never ask for/submit password')


class QRProvisionTests(unittest.IsolatedAsyncioTestCase):
    def private_dirs(self, root):
        root = Path(root).resolve()
        config, session = root / 'config', root / 'session'
        config.mkdir(mode=0o700)
        session.mkdir(mode=0o700)
        _save_private_config(config / 'login.json', json.dumps(dict(version=1, api_id=12345,
                             api_hash='a'*32, phone=PHONE)).encode())
        return config, session

    async def invoke(self, config, session, *, qr_opts=None, confirm='QR',
                     cancel_display=False, config_failure=False, disconnect_failure=False):
        clients, display_calls = [], []
        def factory(*args, **kwargs):
            client = FakeClient(*args, **kwargs)
            client.qr = FakeQR(client, **(qr_opts or {}))
            if disconnect_failure:
                original = client.disconnect
                async def fail_disconnect():
                    await original()
                    raise OSError('fake-sensitive-' + FAKE_URI)
                client.disconnect = fail_disconnect
            clients.append(client)
            return client
        @contextlib.contextmanager
        def display(uri, seconds):
            self.assertTrue(clients[0].qr.started.is_set())
            self.assertEqual(uri, FAKE_URI)
            self.assertTrue(0 < seconds <= 120)
            display_calls.append(True)
            if cancel_display:
                raise asyncio.CancelledError
            clients[0].qr.approved.set()
            yield
        self.clients, self.display_calls = clients, display_calls
        self.output = io.StringIO()
        with contextlib.redirect_stderr(self.output), contextlib.ExitStack() as stack:
            if config_failure:
                stack.enter_context(patch('telegram_assistant.telegram_qr_login._save_private_config',
                                          side_effect=LoginSetupError('private_config_write_failed')))
            return await provision_qr_session(config_dir=config, session_dir=session,
                confirm_prompt=lambda _: confirm, display_qr=display, client_factory=factory)

    def assert_settings_intact(self, config, original):
        self.assertEqual((config / 'login.json').read_bytes(), original)
        self.assertEqual((config / 'login.json').stat().st_mode & 0o777, 0o600)
        self.assertNotIn(FAKE_URI, self.output.getvalue())
        self.assertNotIn('a'*32, self.output.getvalue())
        self.assertNotIn(PHONE, self.output.getvalue())

    def assert_saved_key(self, session):
        path = session / 'assistant.session'
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        reopened = SQLiteSession(str(path.with_suffix('')))
        try:
            self.assertEqual(reopened.auth_key.key, FAKE_KEY)
        finally:
            reopened.close()

    async def test_success_commits_sqlite_key_and_saves_private_config(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            original = (config / 'login.json').read_bytes()
            await self.invoke(config, session)
            self.assert_saved_key(session)
            result = config / 'telegram.json'
            self.assertEqual(result.stat().st_mode & 0o777, 0o600)
            self.assertEqual(set(json.loads(result.read_text())), {'api_id','api_hash','session_file'})
            self.assertNotIn(FAKE_URI, result.read_text())
            self.assert_settings_intact(config, original)
            self.assertTrue(self.clients[0].kwargs['receive_updates'])
            self.assertEqual(self.clients[0].kwargs['request_retries'], 0)
            self.assertEqual(self.clients[0].exports, 1)
            self.assertEqual(self.clients[0].disconnects, 1)

    async def test_password_needed_stops_without_prompt_or_fallback(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            original = (config / 'login.json').read_bytes()
            with self.assertRaises(LoginSetupError) as raised:
                await self.invoke(config, session, qr_opts={'error': SessionPasswordNeededError(None)})
            self.assertEqual(raised.exception.code, 'telegram_qr_password_required')
            self.assertFalse(list(session.iterdir()))
            self.assertFalse((config / 'telegram.json').exists())
            self.assertEqual(self.clients[0].exports, 1)
            self.assert_settings_intact(config, original)

    async def test_expired_or_invalid_expiry_never_displays_or_reexports(self):
        for expiry, expected in ((-1,'telegram_qr_expired'),(121,'telegram_qr_invalid_expiry')):
            with self.subTest(expiry=expiry), tempfile.TemporaryDirectory() as root:
                config, session = self.private_dirs(root)
                with self.assertRaises(LoginSetupError) as raised:
                    await self.invoke(config, session, qr_opts={'expiry': expiry})
                self.assertEqual(raised.exception.code, expected)
                self.assertFalse(self.display_calls)
                self.assertFalse(list(session.iterdir()))
                self.assertEqual(self.clients[0].exports, 1)

    async def test_wait_timeout_cleans_unfinished_session_without_refresh(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            with self.assertRaises(LoginSetupError) as raised:
                await self.invoke(config, session, qr_opts={'error': TimeoutError(FAKE_URI)})
            self.assertEqual(raised.exception.code, 'telegram_qr_expired')
            self.assertFalse(list(session.iterdir()))
            self.assertEqual(self.clients[0].exports, 1)
            self.assertNotIn(FAKE_URI, str(raised.exception))

    async def test_flood_or_rpc_failure_is_safe_and_never_retried(self):
        for error, code in ((FloodWaitError(None,capture=42),'telegram_flood_wait'),
                            (RPCError(None,FAKE_URI,code=500),'telegram_rpc_rejected_qr_wait')):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as root:
                config, session = self.private_dirs(root)
                before=(config/'login.json').read_bytes()
                with self.assertRaises(LoginSetupError) as raised:
                    await self.invoke(config,session,qr_opts={'error':error})
                self.assertEqual(raised.exception.code,code)
                self.assertNotIn(FAKE_URI,str(raised.exception))
                self.assertEqual(self.clients[0].exports,1)
                self.assertFalse(list(session.iterdir()))
                self.assert_settings_intact(config,before)
                if code=='telegram_flood_wait':
                    self.assertEqual(raised.exception.retry_after_seconds,42)

    async def test_cancel_before_consent_never_creates_client(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            with self.assertRaises(LoginSetupError) as raised:
                await self.invoke(config, session, confirm='CANCEL')
            self.assertEqual(raised.exception.code, 'cancelled')
            self.assertEqual(self.clients, [])
            self.assertFalse(list(session.iterdir()))

    async def test_cancel_while_displayed_keeps_settings_cleans_session(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            original = (config / 'login.json').read_bytes()
            with self.assertRaises(asyncio.CancelledError):
                await self.invoke(config, session, cancel_display=True)
            self.assertFalse(list(session.iterdir()))
            self.assert_settings_intact(config, original)

    async def test_wrong_or_unverifiable_account_quarantines_authorized_session(self):
        for phone, expected in (('15559876543','telegram_qr_account_mismatch'),
                                (None,'telegram_qr_account_unverifiable')):
            with self.subTest(phone=phone), tempfile.TemporaryDirectory() as root:
                config, session = self.private_dirs(root)
                with self.assertRaises(LoginSetupError) as raised:
                    await self.invoke(config, session, qr_opts={'phone':phone})
                self.assertEqual(raised.exception.code, expected)
                self.assert_saved_key(session)
                self.assertFalse((config / 'telegram.json').exists())

    async def test_config_or_disconnect_failure_retains_authorized_session(self):
        for scenario in ('config','disconnect'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as root:
                config, session = self.private_dirs(root)
                with self.assertRaises(LoginSetupError):
                    await self.invoke(config, session, config_failure=scenario=='config',
                                      disconnect_failure=scenario=='disconnect')
                self.assert_saved_key(session)
                self.assertFalse((config / 'telegram.json').exists())

    async def test_existing_session_or_config_is_never_overwritten(self):
        for target in ('session','config'):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as root:
                config, session = self.private_dirs(root)
                path = session/'assistant.session' if target=='session' else config/'telegram.json'
                path.write_bytes(b'fake-existing')
                with self.assertRaises(LoginSetupError) as raised:
                    await self.invoke(config, session)
                self.assertEqual(raised.exception.code,'target_already_exists')
                self.assertEqual(path.read_bytes(),b'fake-existing')
                self.assertEqual(self.clients,[])

    async def test_missing_settings_or_provision_lock_fails_before_client(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            with _provision_lock(config), self.assertRaises(LoginSetupError) as raised:
                await self.invoke(config,session)
            self.assertEqual(raised.exception.code,'provision_already_running')
            (config/'login.json').unlink()
            with self.assertRaises(LoginSetupError) as raised:
                await self.invoke(config,session)
            self.assertEqual(raised.exception.code,'login_settings_required')
            self.assertEqual(self.clients,[])
