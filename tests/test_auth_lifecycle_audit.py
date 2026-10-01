"""Real pinned SDK auth methods, request loop and DC switch; fake transport only."""
import asyncio
import contextlib
from datetime import datetime, timezone
import io
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from telethon import TelegramClient, errors, functions, types
from telethon.sessions import MemorySession

from telegram_assistant.telegram_login import _safe_login_failure

PHONE, OTP, PASSWORD = '+15555550100', '98765', '  fake_秘密_$pass  '


class AuthHarness:
    def __init__(self, *, retries=0, migrate=False, invalid=False):
        self.client = TelegramClient(MemorySession(),12345,'a'*32,receive_updates=False,
            request_retries=retries,connection_retries=1,flood_sleep_threshold=0,
            raise_last_call_error=True)
        self.client.session.set_dc(2,'192.0.2.2',443)
        self.calls, self.migrations, self.keys = [], [], []
        self.connected, self.authorized = False, False
        self.migrate, self.invalid = migrate, invalid
        self.user = types.User(id=123456,is_self=True,bot=False,access_hash=12345,
                               first_name='fake-only',phone=PHONE[1:])
        self.client.connect = self.connect
        self.client._disconnect = self.disconnect
        self.client.is_connected = lambda: self.connected
        self.client._get_dc = AsyncMock(side_effect=lambda dc: SimpleNamespace(id=dc,
                                             ip_address='192.0.2.4',port=443))
        self.client._sender.send = self.send

    async def connect(self):
        self.connected = True
        if not self.client._sender.auth_key:
            fake_key = bytes([self.client.session.dc_id])*256
            self.client._sender.auth_key.key = fake_key
            self.client.session.auth_key = self.client._sender.auth_key
            self.keys.append(fake_key)
    async def disconnect(self):
        self.connected = False
    def send(self, request, ordered=False):
        if isinstance(request,functions.InvokeWithoutUpdatesRequest):
            request=request.query
        label=type(request).__name__
        self.calls.append((label,self.client.session.dc_id))
        future=asyncio.get_running_loop().create_future()
        try:
            if isinstance(request,functions.users.GetUsersRequest):
                if not self.authorized:
                    raise errors.UnauthorizedError(request,'fake AUTH_KEY_UNREGISTERED',code=401)
                result=[self.user]
            elif isinstance(request,functions.auth.SendCodeRequest):
                if self.migrate:
                    self.migrate=False
                    self.migrations.append(True)
                    raise errors.PhoneMigrateError(request,capture=4)
                result=types.auth.SentCode(type=types.auth.SentCodeTypeApp(length=5),phone_code_hash='fake-code-hash')
            elif isinstance(request,functions.auth.SignInRequest):
                assert request.phone_number==PHONE[1:] and request.phone_code_hash=='fake-code-hash' and request.phone_code==OTP
                raise errors.SessionPasswordNeededError(request)
            elif isinstance(request,functions.account.GetPasswordRequest):
                result=SimpleNamespace(fake_only=True)
            elif isinstance(request,functions.auth.CheckPasswordRequest):
                if self.invalid:
                    raise errors.PasswordHashInvalidError(request)
                self.authorized=True
                result=types.auth.Authorization(user=self.user)
            elif isinstance(request,functions.updates.GetStateRequest):
                if not self.authorized:
                    raise errors.UnauthorizedError(request,'fake AUTH_KEY_UNREGISTERED',code=401)
                result=types.updates.State(pts=0,qts=0,date=datetime.now(timezone.utc),seq=0,unread_count=0)
            elif isinstance(request,functions.updates.GetDifferenceRequest):
                result=types.updates.DifferenceEmpty(date=datetime.now(timezone.utc),seq=0)
            else:
                raise AssertionError('unexpected fake RPC type')
        except Exception as exc:
            future.set_exception(exc)
        else:
            future.set_result(result)
        return future


class SDKLifecycleAudit(unittest.IsolatedAsyncioTestCase):
    async def stock_start(self,harness):
        prompts=[]
        def code():
            prompts.append('code')
            return OTP
        def password():
            prompts.append('password')
            return PASSWORD
        with patch('telethon.password.compute_check',return_value=types.InputCheckPasswordEmpty()) as srp:
            with contextlib.redirect_stdout(io.StringIO()),contextlib.redirect_stderr(io.StringIO()):
                await harness.client.start(phone=PHONE,code_callback=code,password=password,max_attempts=1)
            srp.assert_called_once()
            self.assertEqual(srp.call_args.args[1],PASSWORD)
        return prompts

    async def test_standard_start_preserves_client_dc_key_and_password(self):
        h=AuthHarness()
        prompts=await self.stock_start(h)
        self.assertEqual(prompts,['code','password'])
        labels=[name for name,_dc in h.calls]
        self.assertEqual([x for x in labels if x in ('SendCodeRequest','SignInRequest','GetPasswordRequest','CheckPasswordRequest')],
                         ['SendCodeRequest','SignInRequest','GetPasswordRequest','CheckPasswordRequest'])
        self.assertTrue(all(dc==2 for _,dc in h.calls))
        self.assertEqual(len(h.keys),1)
        self.assertEqual(h.client.session.auth_key.key,h.keys[0])
        self.assertEqual(h.client._request_retries,0)
        self.assertTrue(h.client._no_updates)

    async def test_current_manual_signin_has_same_auth_request_sequence(self):
        h=AuthHarness()
        await h.client.connect()
        self.assertFalse(await h.client.is_user_authorized())
        sent=await h.client.send_code_request(PHONE)
        with self.assertRaises(errors.SessionPasswordNeededError):
            await h.client.sign_in(phone=PHONE,code=OTP,phone_code_hash=sent.phone_code_hash)
        with patch('telethon.password.compute_check',return_value=types.InputCheckPasswordEmpty()) as srp:
            await h.client.sign_in(password=PASSWORD)
        self.assertEqual(srp.call_args.args[1],PASSWORD)
        self.assertEqual([name for name,_ in h.calls if name in ('SendCodeRequest','SignInRequest','GetPasswordRequest','CheckPasswordRequest')],
                         ['SendCodeRequest','SignInRequest','GetPasswordRequest','CheckPasswordRequest'])
        self.assertEqual(len(h.keys),1)

    async def test_zero_retry_dc_migration_stops_before_code_or_password(self):
        h=AuthHarness(migrate=True)
        with self.assertRaises(errors.PhoneMigrateError) as raised:
            await self.stock_start(h)
        self.assertEqual(h.client.session.dc_id,4)
        self.assertEqual(len(h.keys),2)
        self.assertEqual(h.client.session.auth_key.key,h.keys[-1])
        self.assertFalse(any(name in ('SignInRequest','GetPasswordRequest','CheckPasswordRequest') for name,_ in h.calls))
        self.assertEqual(_safe_login_failure(raised.exception,'send_code').code,'telegram_rpc_rejected_send_code')

    async def test_one_retry_completes_sdk_migration_before_password(self):
        h=AuthHarness(retries=1,migrate=True)
        prompts=await self.stock_start(h)
        self.assertEqual(prompts,['code','password'])
        self.assertEqual(h.client.session.dc_id,4)
        self.assertTrue(all(dc==4 for name,dc in h.calls if name in ('SignInRequest','GetPasswordRequest','CheckPasswordRequest')))
        self.assertEqual(len(h.keys),2)

    async def test_invalid_password_mapping_is_exact_and_start_does_not_loop(self):
        h=AuthHarness(invalid=True)
        with self.assertRaises(errors.PasswordHashInvalidError) as raised:
            await self.stock_start(h)
        self.assertEqual(sum(name=='CheckPasswordRequest' for name,_ in h.calls),1)
        self.assertEqual(_safe_login_failure(raised.exception,'sign_in_password').code,'telegram_password_invalid')
        self.assertIsNone(raised.exception.request)  # SDK start replaces the original RPC error.
