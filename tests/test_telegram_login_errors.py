import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from telethon import errors

from telegram_assistant.telegram_login import LoginSetupError, provision_session
from test_telegram_login import FakeClient, API_ID, API_HASH, PHONE, PASSWORD

OTP = "98765"


class LoginSettingsAndErrors(unittest.IsolatedAsyncioTestCase):
    def private_dirs(self, root):
        root = Path(root).resolve()
        config, session = root / "config", root / "session"
        config.mkdir(mode=0o700)
        session.mkdir(mode=0o700)
        return config, session

    async def invoke(self, config, session, *, client=FakeClient, answers=None, **kwargs):
        answer_iter = iter(answers or [API_ID, API_HASH, PHONE, OTP])
        prompts, output = [], io.StringIO()
        def prompt(label):
            prompts.append(label)
            return next(answer_iter)
        with contextlib.redirect_stderr(output):
            result = await provision_session(
                config_dir=config, session_dir=session, client_factory=client,
                secret_prompt=prompt, confirm_prompt=lambda _: "SEND", **kwargs,
            )
        return result, prompts, output.getvalue()

    async def test_no_password_required_success_never_prompts_password(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            _, prompts, output = await self.invoke(config, session)
            self.assertEqual(len(prompts), 4)
            self.assertFalse(any("password" in prompt for prompt in prompts))
            self.assertNotIn("SESSION_PASSWORD_NEEDED", output)

    async def test_credentials_saved_before_request_survive_failure_and_are_reused(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            class InvalidCode(FakeClient):
                async def connect(client):
                    self.assertTrue((config / "login.json").exists())
                    client.session_path.write_bytes(b"fake-incomplete-session")
                async def sign_in(client, **kwargs):
                    raise errors.PhoneCodeInvalidError(request=None)
            with self.assertRaises(LoginSetupError) as raised:
                await self.invoke(config, session, client=InvalidCode)
            self.assertEqual(raised.exception.code, "telegram_code_invalid")
            saved = config / "login.json"
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(saved.read_text()), dict(version=1, api_id=int(API_ID), api_hash=API_HASH, phone=PHONE))
            self.assertNotIn(OTP, saved.read_text())
            self.assertEqual(list(session.iterdir()), [])
            _, prompts, output = await self.invoke(config, session, answers=[OTP])
            self.assertEqual(prompts, ["Telegram login code (hidden): "])
            self.assertIn("loaded from private login.json", output)
            self.assertNotIn(API_HASH, output)
            self.assertNotIn(PHONE, output)

    async def test_configure_only_never_contacts_telegram_or_prompts_confirmation(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            def forbidden(*args, **kwargs):
                self.fail("network/client must not be created")
            _, prompts, _ = await self.invoke(config, session, client=forbidden,
                                              answers=[API_ID, API_HASH, PHONE], configure_only=True)
            self.assertEqual(len(prompts), 3)
            first = (config / "login.json").read_bytes()
            _, prompts, _ = await self.invoke(config, session, client=forbidden,
                                              answers=["must-not-be-read"], configure_only=True)
            self.assertEqual(prompts, [])
            self.assertEqual((config / "login.json").read_bytes(), first)

    async def test_replacement_is_explicit_atomic_and_keeps_old_on_validation_error(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            await self.invoke(config, session, configure_only=True)
            original = (config / "login.json").read_bytes()
            with self.assertRaises(LoginSetupError):
                await self.invoke(config, session, configure_only=True, replace_login_config=True,
                                  answers=[API_ID, "bad-hash", PHONE])
            self.assertEqual((config / "login.json").read_bytes(), original)
            await self.invoke(config, session, configure_only=True, replace_login_config=True,
                              answers=["54321", "b" * 32, "+15555550101"])
            saved = config / "login.json"
            self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(saved.read_text())["api_id"], 54321)
            self.assertFalse(any(p.name.startswith(".telegram-config-") for p in config.iterdir()))

    async def test_unsafe_or_malformed_saved_settings_fail_before_prompt_or_rpc(self):
        for scenario in ("symlink", "permissions", "unknown_key", "duplicate_key", "hardlink", "oversize"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as root:
                config, session = self.private_dirs(root)
                saved = config / "login.json"
                document = dict(version=1, api_id=int(API_ID), api_hash=API_HASH, phone=PHONE)
                if scenario == "unknown_key":
                    document["otp"] = OTP
                saved.write_text(json.dumps(document))
                saved.chmod(0o600)
                if scenario == "symlink":
                    saved.rename(config / "real.json")
                    saved.symlink_to(config / "real.json")
                elif scenario == "permissions":
                    saved.chmod(0o644)
                elif scenario == "duplicate_key":
                    saved.write_text('{"version":1,"version":1}')
                elif scenario == "oversize":
                    saved.write_text("x" * 4097)
                elif scenario == "hardlink":
                    import os
                    os.link(saved, config / "copy.json")
                with self.assertRaises(LoginSetupError) as raised:
                    await self.invoke(config, session, answers=["must-not-be-read"],
                                      client=lambda *a, **k: self.fail("client must not be created"))
                self.assertIn(raised.exception.code, {"unsafe_login_config", "login_config_invalid"})
                self.assertFalse(list(session.iterdir()))

    async def test_real_typed_code_errors_do_not_trigger_password_prompt(self):
        cases = (
            (errors.PhoneCodeInvalidError(None), "telegram_code_invalid"),
            (errors.PhoneCodeExpiredError(None), "telegram_code_expired"),
            (errors.PasswordHashInvalidError(None), "telegram_password_invalid"),
            (errors.UnauthorizedError(None, "fake-only-sensitive-" + API_HASH), "telegram_authorization_rejected_sign_in_code"),
            (errors.RPCError(None, "fake-only-sensitive-" + PHONE, code=500), "telegram_rpc_rejected_sign_in_code"),
            (errors.FloodWaitError(None, capture=42), "telegram_flood_wait"),
            (errors.AuthRestartError(None), "telegram_auth_restart_required"),
        )
        for error, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as root:
                config, session = self.private_dirs(root)
                class Rejected(FakeClient):
                    async def sign_in(client, **kwargs):
                        raise error
                with self.assertRaises(LoginSetupError) as raised:
                    await self.invoke(config, session, client=Rejected)
                self.assertEqual(raised.exception.code, expected)
                self.assertNotIn(API_HASH, str(raised.exception))
                self.assertNotIn(PHONE, str(raised.exception))
                if expected == "telegram_flood_wait":
                    self.assertEqual(raised.exception.retry_after_seconds, 42)
                self.assertTrue((config / "login.json").exists())

    async def test_password_prompt_io_failure_is_not_reported_as_wrong_password(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            answers = iter([API_ID, API_HASH, PHONE, OTP])
            calls = []
            class PasswordNeeded(FakeClient):
                async def sign_in(client, **kwargs):
                    calls.append(kwargs)
                    raise errors.SessionPasswordNeededError(None)
            def secret(prompt):
                if "password" in prompt:
                    raise OSError("fake-only-" + PASSWORD)
                return next(answers)
            with contextlib.redirect_stderr(io.StringIO()) as output, self.assertRaises(LoginSetupError) as raised:
                await provision_session(config_dir=config, session_dir=session, client_factory=PasswordNeeded,
                                        secret_prompt=secret, confirm_prompt=lambda _: "SEND")
            self.assertEqual(raised.exception.code, "terminal_input_failed")
            self.assertEqual(len(calls), 1)
            self.assertNotIn(PASSWORD, output.getvalue())
            self.assertTrue((config / "login.json").exists())

    async def test_password_needed_is_exact_typed_trigger_and_empty_stops(self):
        with tempfile.TemporaryDirectory() as root:
            config, session = self.private_dirs(root)
            calls = []
            class PasswordNeeded(FakeClient):
                async def sign_in(client, **kwargs):
                    calls.append(kwargs)
                    raise errors.SessionPasswordNeededError(None)
            with self.assertRaises(LoginSetupError) as raised:
                await self.invoke(config, session, client=PasswordNeeded,
                                  answers=[API_ID, API_HASH, PHONE, OTP, ""])
            self.assertEqual(raised.exception.code, "telegram_password_required")
            self.assertEqual(len(calls), 1)
            self.assertNotIn("password", calls[0])
            self.assertTrue((config / "login.json").exists())

    async def test_password_rpc_errors_have_safe_distinct_causes(self):
        for error, expected in (
            (errors.PasswordHashInvalidError(None), "telegram_password_invalid"),
            (errors.RPCError(None, PASSWORD, code=500), "telegram_rpc_rejected_sign_in_password"),
            (TimeoutError(PASSWORD), "telegram_timeout_sign_in_password"),
        ):
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as root:
                config, session = self.private_dirs(root)
                class PasswordRejected(FakeClient):
                    async def sign_in(client, **kwargs):
                        if "password" not in kwargs:
                            raise errors.SessionPasswordNeededError(None)
                        raise error
                with self.assertRaises(LoginSetupError) as raised:
                    await self.invoke(config, session, client=PasswordRejected,
                                      answers=[API_ID, API_HASH, PHONE, OTP, PASSWORD])
                self.assertEqual(raised.exception.code, expected)
                self.assertNotIn(PASSWORD, str(raised.exception))
                self.assertNotIn(PASSWORD, (config / "login.json").read_text())


if __name__ == "__main__":
    unittest.main()
