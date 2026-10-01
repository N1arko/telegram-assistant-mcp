import asyncio
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from telethon import errors, functions, types
from telethon.sessions import SQLiteSession

from test_auth_lifecycle_audit import AuthHarness, PHONE, OTP, PASSWORD
from telegram_assistant.telegram_login import LoginSetupError, _save_private_config
from telegram_assistant.telegram_standard_login import (
    _ProbeClient, ProbeState, provision_standard_session,
)
from telegram_assistant.telegram_qr_login import _provision_lock


class StandardHarness(AuthHarness):
    def __init__(self, path, api_id, api_hash, *, mode='2fa', **kwargs):
        super().__init__()
        assert api_id == 12345 and api_hash == 'a'*32
        self.client = _ProbeClient(path, api_id, api_hash, **kwargs)
        self.client.session.set_dc(2, '192.0.2.2', 443)
        self.client.connect = self.connect  # Only network connection is fake.
        async def close():
            self.connected = False
            self.client.session.close()
        self.client._disconnect = close
        self.client.is_connected = lambda: self.connected
        self.client._get_dc = self.fake_dc
        self.client._sender.send = self.send
        self.mode = mode
        self.invalid = mode == 'password_invalid'
        self.migrate = mode == 'migration'
    async def fake_dc(self, dc):
        from types import SimpleNamespace
        return SimpleNamespace(id=dc, ip_address='192.0.2.4', port=443)
    def send(self, request, ordered=False):
        raw = request.query if isinstance(request, functions.InvokeWithoutUpdatesRequest) else request
        error = None
        if isinstance(raw, functions.auth.SendCodeRequest):
            if self.mode == 'flood':
                error = errors.FloodWaitError(raw, capture=37)
            elif self.mode == 'auth_restart':
                error = errors.AuthRestartError(raw)
        if isinstance(raw, functions.auth.SignInRequest):
            if self.mode == 'code_invalid':
                error = errors.PhoneCodeInvalidError(raw)
            elif self.mode == 'no2fa':
                self.calls.append(('SignInRequest', self.client.session.dc_id))
                self.authorized = True
                future = asyncio.get_running_loop().create_future()
                future.set_result(types.auth.Authorization(user=self.user))
                return future
        if isinstance(raw, functions.updates.GetStateRequest) and self.mode == 'post_accept_error':
            error = errors.RPCError(raw, 'fake-sensitive-rpc-text', code=500)
        if error is not None:
            self.calls.append((type(raw).__name__, self.client.session.dc_id))
            future = asyncio.get_running_loop().create_future()
            future.set_exception(error)
            return future
        return super().send(request, ordered)


class StandardProvisionTests(unittest.IsolatedAsyncioTestCase):
    def dirs(self, root):
        root = Path(root).resolve()
        config, session = root/'config', root/'session'
        config.mkdir(mode=0o700)
        session.mkdir(mode=0o700)
        _save_private_config(config/'login.json', json.dumps(dict(version=1, api_id=12345,
            api_hash='a'*32, phone=PHONE)).encode())
        return config, session
    async def invoke(self, config, session, *, mode='2fa', confirm='SEND',
                     password=PASSWORD, account_mismatch=False, config_failure=False):
        self.state, self.h, self.prompts = ProbeState(), None, []
        def factory(*args, **kwargs):
            self.h = StandardHarness(*args, mode=mode, **kwargs)
            if account_mismatch:
                self.h.user.phone = '15557654321'
            return self.h.client
        def secret(prompt):
            self.prompts.append('code' if 'login code' in prompt else 'password')
            return OTP if 'login code' in prompt else password
        self.output = io.StringIO()
        with contextlib.redirect_stdout(self.output), contextlib.redirect_stderr(self.output), contextlib.ExitStack() as stack:
            stack.enter_context(patch('telethon.password.compute_check', return_value=types.InputCheckPasswordEmpty()))
            if config_failure:
                stack.enter_context(patch('telegram_assistant.telegram_standard_login._save_private_config',
                    side_effect=LoginSetupError('private_config_write_failed')))
            result = await provision_standard_session(config_dir=config, session_dir=session,
                state=self.state, confirm_prompt=lambda _:confirm, secret_prompt=secret,
                client_factory=factory)
        for value in (PHONE, OTP, PASSWORD, 'a'*32, 'fake-only', 'fake-sensitive-rpc-text'):
            self.assertNotIn(value, self.output.getvalue())
        return result
    def assert_key_saved(self, session):
        self.assertEqual((session/'assistant.session').stat().st_mode & 0o777, 0o600)
        reopened = SQLiteSession(str(session/'assistant'))
        try:
            self.assertEqual(reopened.auth_key.key, self.h.keys[-1])
        finally:
            reopened.close()

    async def test_stock_start_success_2fa_and_no2fa_commits_for_service(self):
        for mode, prompts in [('2fa',['code','password']), ('no2fa',['code'])]:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                config, session = self.dirs(root)
                original = (config/'login.json').read_bytes()
                await self.invoke(config, session, mode=mode)
                self.assertEqual(self.prompts, prompts)
                self.assertTrue(self.state.accepted)
                self.assert_key_saved(session)
                runtime = json.loads((config/'telegram.json').read_text())
                self.assertEqual(set(runtime), {'api_id','api_hash','session_file'})
                self.assertEqual(runtime['session_file'], str(session/'assistant.session'))
                self.assertEqual((config/'telegram.json').stat().st_mode & 0o777, 0o600)
                self.assertEqual((config/'login.json').read_bytes(), original)
                self.assertEqual(sum(n=='SendCodeRequest' for n,_ in self.h.calls), 1)
                self.assertEqual(sum(n=='CheckPasswordRequest' for n,_ in self.h.calls), int(mode=='2fa'))

    async def test_failures_map_actual_rpc_and_do_not_retry_or_leave_session(self):
        cases = [('password_invalid','telegram_password_invalid','check_password',['code','password']),
                 ('code_invalid','telegram_code_invalid','sign_in_code',['code']),
                 ('migration','telegram_rpc_rejected_send_code','send_code',[]),
                 ('flood','telegram_flood_wait','send_code',[]),
                 ('auth_restart','standard_attempt_limit','send_code',[])]
        for mode, code, rpc, prompts in cases:
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                config, session = self.dirs(root)
                original = (config/'login.json').read_bytes()
                with self.assertRaises(LoginSetupError) as raised:
                    await self.invoke(config, session, mode=mode)
                self.assertEqual(raised.exception.code, code)
                self.assertEqual(self.state.last_rpc, rpc)
                self.assertEqual(self.prompts, prompts)
                self.assertEqual(self.state.dc_changed, mode=='migration')
                self.assertLessEqual(sum(n=='SendCodeRequest' for n,_ in self.h.calls), 1)
                self.assertLessEqual(sum(n=='CheckPasswordRequest' for n,_ in self.h.calls), 1)
                self.assertFalse((session/'assistant.session').exists())
                self.assertFalse((config/'telegram.json').exists())
                self.assertEqual((config/'login.json').read_bytes(), original)
                if mode=='flood':
                    self.assertEqual(raised.exception.retry_after_seconds, 37)

    async def test_cancel_before_client_and_empty_password_before_second_code(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.dirs(root)
            with self.assertRaises(LoginSetupError) as raised:
                await self.invoke(config, session, confirm='CANCEL')
            self.assertEqual(raised.exception.code,'cancelled')
            self.assertIsNone(self.h)
            with self.assertRaises(LoginSetupError) as raised:
                await self.invoke(config, session, password='')
            self.assertEqual(raised.exception.code,'cancelled')
            self.assertEqual(sum(n=='SendCodeRequest' for n,_ in self.h.calls),1)
            self.assertFalse(any(n=='CheckPasswordRequest' for n,_ in self.h.calls))
            self.assertFalse((session/'assistant.session').exists())

    async def test_accepted_session_retained_on_post_accept_error_mismatch_or_write_failure(self):
        cases = [dict(mode='post_accept_error'), dict(account_mismatch=True), dict(config_failure=True)]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as root:
                config, session = self.dirs(root)
                with self.assertRaises(LoginSetupError):
                    await self.invoke(config,session,**case)
                self.assertTrue(self.state.accepted)
                self.assert_key_saved(session)
                self.assertFalse((config/'telegram.json').exists())
                with self.assertRaises(LoginSetupError) as raised:
                    await self.invoke(config,session)
                self.assertEqual(raised.exception.code,'target_already_exists')
                self.assertIsNone(self.h)

    async def test_existing_target_missing_settings_and_lock_block_before_network(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.dirs(root)
            with _provision_lock(config):
                with self.assertRaises(LoginSetupError) as raised:
                    await self.invoke(config,session)
            self.assertEqual(raised.exception.code,'provision_already_running')
            self.assertIsNone(self.h)
            (config/'login.json').unlink()
            with self.assertRaises(LoginSetupError) as raised:
                await self.invoke(config,session)
            self.assertEqual(raised.exception.code,'login_settings_required')
            self.assertIsNone(self.h)
