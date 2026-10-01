import json
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from argparse import Namespace
from unittest.mock import AsyncMock, Mock, patch

from telethon.errors import SessionPasswordNeededError

from telegram_assistant.telegram_login import (
    LoginSetupError, _TTYConsole, _confirmed_send, _run, provision_session,
)


API_ID = "12345"
API_HASH = "a" * 32
PHONE = "+15555550100"
CODE = "12345"
PASSWORD = "test-only-two-step-password"


class FakeClient:
    def __init__(self, session, api_id, api_hash, **kwargs):
        self.session_path = Path(session + ".session")
        self.api_id = api_id
        self.api_hash = api_hash
        self.kwargs = kwargs
        self.authorized = False
        self.signin_calls = []

    async def connect(self):
        return None

    async def is_user_authorized(self):
        return self.authorized

    async def send_code_request(self, phone):
        return SimpleNamespace(phone_code_hash="fake-test-code-hash")

    def _save_test_session(self):
        with self.session_path.open("xb") as f:
            f.write(b"mock-authorized-session")

    async def sign_in(self, **kwargs):
        self.signin_calls.append(kwargs)
        self.authorized = True
        self._save_test_session()
        return object()

    async def disconnect(self):
        return None


class TerminalFlagTests(unittest.TestCase):
    def terminal_flags(self):
        return SimpleNamespace(
            ICRNL=0x100, INLCR=0x40, IGNCR=0x80, ISTRIP=0x20,
            ICANON=2, ECHO=8, ECHONL=0x40, TCSAFLUSH=2,
            tcgetattr=Mock(return_value=[0, 0, 0, 0, 0, 0, []]),
            tcsetattr=Mock(),
        )

    def test_utf8_flag_uses_native_constant_or_linux_fallback(self):
        for platform, native, expected in (("linux", None, 0x4000), ("darwin", 0x8000, 0x8000)):
            with self.subTest(platform=platform):
                flags = self.terminal_flags()
                if native is not None:
                    flags.IUTF8 = native
                console = _TTYConsole()
                console.fd = 7
                with patch("telegram_assistant.telegram_login.termios", flags), \
                     patch("telegram_assistant.telegram_login.sys.platform", platform), \
                     patch("telegram_assistant.telegram_login.os.write"), \
                     patch("telegram_assistant.telegram_login.os.read", side_effect=[b"x", b"\n"]):
                    self.assertEqual(console.read("Test prompt: ", hidden=True), "x")
                self.assertEqual(flags.tcsetattr.call_args_list[0].args[2][0] & expected, expected)
                self.assertEqual(flags.tcsetattr.call_args_list[0].args[2][3] & flags.ECHO, 0)
                self.assertEqual(flags.tcsetattr.call_args_list[-1].args[2], [0, 0, 0, 0, 0, 0, []])

    def test_unknown_platform_without_utf8_flag_fails_before_reading(self):
        flags = self.terminal_flags()
        console = _TTYConsole()
        console.fd = 7
        with patch("telegram_assistant.telegram_login.termios", flags), \
             patch("telegram_assistant.telegram_login.sys.platform", "unsupported"), \
             patch("telegram_assistant.telegram_login.os.read") as read:
            with self.assertRaises(LoginSetupError) as raised:
                console.read("Test prompt: ", hidden=True)
        self.assertEqual(raised.exception.code, "utf8_terminal_flag_unavailable")
        flags.tcsetattr.assert_not_called()
        read.assert_not_called()


class LoginProvisionTests(unittest.IsolatedAsyncioTestCase):
    def private_dirs(self, root):
        root = Path(root).resolve()
        config_dir = root / "config"
        session_dir = root / "session"
        config_dir.mkdir(mode=0o700)
        session_dir.mkdir(mode=0o700)
        config_dir.chmod(0o700)
        session_dir.chmod(0o700)
        return config_dir, session_dir

    async def test_saves_only_new_private_session_and_config(self):
        with tempfile.TemporaryDirectory() as root:
            config_dir, session_dir = self.private_dirs(root)
            answers = iter([API_ID, API_HASH, PHONE, CODE])
            clients = []

            def factory(*args, **kwargs):
                client = FakeClient(*args, **kwargs)
                clients.append(client)
                return client

            config_path, session_path = await provision_session(
                config_dir=config_dir, session_dir=session_dir,
                secret_prompt=lambda _prompt: next(answers),
                confirm_prompt=lambda _prompt: "SEND",
                client_factory=factory,
            )

            document = json.loads(config_path.read_text())
            self.assertEqual(document, {
                "api_id": int(API_ID), "api_hash": API_HASH,
                "session_file": str(session_dir / "assistant.session"),
            })
            self.assertEqual(config_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(session_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(clients[0].kwargs["receive_updates"], False)
            self.assertEqual(clients[0].kwargs["request_retries"], 0)
            self.assertEqual(clients[0].signin_calls, [{
                "phone": PHONE, "code": CODE,
                "phone_code_hash": "fake-test-code-hash",
            }])

    async def test_two_step_password_is_prompted_separately_and_never_echoed(self):
        with tempfile.TemporaryDirectory() as root:
            config_dir, session_dir = self.private_dirs(root)
            answers = iter([API_ID, API_HASH, PHONE, CODE, PASSWORD])

            class TwoStepClient(FakeClient):
                async def sign_in(self, **kwargs):
                    self.signin_calls.append(kwargs)
                    if "password" not in kwargs:
                        raise SessionPasswordNeededError(request=None)
                    self.authorized = True
                    self._save_test_session()

            clients = []
            def factory(*args, **kwargs):
                client = TwoStepClient(*args, **kwargs)
                clients.append(client)
                return client

            await provision_session(
                config_dir=config_dir, session_dir=session_dir,
                secret_prompt=lambda _prompt: next(answers),
                confirm_prompt=lambda _prompt: "SEND", client_factory=factory,
            )
            self.assertEqual(clients[0].signin_calls[-1], {"password": PASSWORD})
            self.assertNotIn(PASSWORD, json.dumps(json.loads((config_dir / "telegram.json").read_text())))

    async def test_confirmation_accepts_whitespace_case_and_bracketed_paste(self):
        for confirmation in (
            "SEND", "  SEND  ", "send", "\tSeNd\r",
            "\x1b[200~SEND\x1b[201~",
            "  \x1b[200~ send \x1b[201~  ",
        ):
            with self.subTest(confirmation=repr(confirmation)), tempfile.TemporaryDirectory() as root:
                config_dir, session_dir = self.private_dirs(root)
                answers = iter([API_ID, API_HASH, PHONE, CODE])
                await provision_session(
                    config_dir=config_dir, session_dir=session_dir,
                    secret_prompt=lambda _prompt: next(answers),
                    confirm_prompt=lambda _prompt: confirmation,
                    client_factory=FakeClient,
                )
                self.assertTrue((session_dir / "assistant.session").exists())

    def test_confirmation_rejects_ambiguous_or_malformed_input(self):
        for confirmation in (
            "", "NO", "SEND PLEASE", "S E N D", "SЕND",  # second character in last value is Cyrillic
            "\x1b[200~SEND", "SEND\x1b[201~", "\x1b[200~NO\x1b[201~",
        ):
            with self.subTest(confirmation=repr(confirmation)):
                self.assertFalse(_confirmed_send(confirmation))

    async def test_cancel_or_invalid_credentials_never_connects(self):
        cases = [
            ([API_ID, API_HASH, PHONE], "CANCEL", "cancelled"),
            ([API_ID, "bad-hash", PHONE], "SEND", "invalid_api_hash"),
        ]
        for answers, confirm, code in cases:
            with self.subTest(code=code), tempfile.TemporaryDirectory() as root:
                config_dir, session_dir = self.private_dirs(root)
                calls = []
                answer_iter = iter(answers)
                with self.assertRaises(LoginSetupError) as raised:
                    await provision_session(
                        config_dir=config_dir, session_dir=session_dir,
                        secret_prompt=lambda _prompt: next(answer_iter),
                        confirm_prompt=lambda _prompt: confirm,
                        client_factory=lambda *a, **k: calls.append((a, k)),
                    )
                self.assertEqual(raised.exception.code, code)
                self.assertFalse(calls)
                self.assertEqual([p.name for p in config_dir.iterdir()],
                                 ["login.json"] if code == "cancelled" else [])
                self.assertEqual(list(session_dir.iterdir()), [])

    async def test_rejected_confirmation_retries_without_reentering_secrets(self):
        with tempfile.TemporaryDirectory() as root:
            config_dir, session_dir = self.private_dirs(root)
            secrets = iter([API_ID, API_HASH, PHONE, CODE])
            confirmations = iter(["", "SЕND", "SEND"])
            with patch("telegram_assistant.telegram_login.sys.stderr", io.StringIO()) as output:
                await provision_session(
                    config_dir=config_dir, session_dir=session_dir,
                    secret_prompt=lambda _prompt: next(secrets),
                    confirm_prompt=lambda _prompt: next(confirmations), client_factory=FakeClient,
                )
            self.assertIn("empty_line", output.getvalue())
            self.assertIn("non_ascii", output.getvalue())
            for value in (API_HASH, PHONE, "SЕND"):
                self.assertNotIn(value, output.getvalue())

    async def test_terminal_check_only_never_reads_account_configuration(self):
        args = Namespace(config_dir=Path("/does-not-exist"), session_dir=Path("/does-not-exist"), check_terminal=True)
        tty = SimpleNamespace(isatty=lambda: True)
        with patch("telegram_assistant.telegram_login.sys.stdin", tty), \
             patch("telegram_assistant.telegram_login.sys.stderr", io.StringIO()) as output, \
             patch("telegram_assistant.telegram_login._TTYConsole") as terminal, \
             patch("telegram_assistant.telegram_login.provision_session", new_callable=AsyncMock) as provision:
            output.isatty = lambda: True
            terminal.return_value.__enter__.return_value.confirmation.return_value = "CHECK"
            await _run(args)
            provision.assert_not_awaited()

    async def test_existing_session_or_config_is_never_overwritten(self):
        for name in ["session", "config"]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as root:
                config_dir, session_dir = self.private_dirs(root)
                target = session_dir / "assistant.session" if name == "session" else config_dir / "telegram.json"
                target.write_bytes(b"preserve")
                target.chmod(0o600)
                prompts = []
                with self.assertRaises(LoginSetupError) as raised:
                    await provision_session(
                        config_dir=config_dir, session_dir=session_dir,
                        secret_prompt=lambda prompt: prompts.append(prompt),
                        client_factory=lambda *a, **k: self.fail("must not connect"),
                    )
                self.assertEqual(raised.exception.code, "target_already_exists")
                self.assertEqual(target.read_bytes(), b"preserve")
                self.assertFalse(prompts)

    async def test_private_directory_permissions_are_required(self):
        with tempfile.TemporaryDirectory() as root:
            config_dir, session_dir = self.private_dirs(root)
            session_dir.chmod(0o755)
            calls = []
            with self.assertRaises(LoginSetupError) as raised:
                await provision_session(
                    config_dir=config_dir, session_dir=session_dir,
                    secret_prompt=lambda _prompt: calls.append("prompt"),
                    client_factory=lambda *a, **k: calls.append("client"),
                )
            self.assertEqual(raised.exception.code, "unsafe_directory")
            self.assertEqual(calls, [])

    async def test_cli_fails_closed_without_stdin_or_stderr_tty(self):
        args = Namespace(config_dir=Path("/run/telegram"), session_dir=Path("/sessions"))
        tty = SimpleNamespace(isatty=lambda: True)
        non_tty = SimpleNamespace(isatty=lambda: False)
        for stdin, stderr in ((io.StringIO(), tty), (tty, non_tty)):
            with self.subTest(stdin_tty=stdin.isatty(), stderr_tty=stderr.isatty()), \
                 patch("telegram_assistant.telegram_login.sys.stdin", stdin), \
                 patch("telegram_assistant.telegram_login.sys.stderr", stderr), \
                 patch("telegram_assistant.telegram_login.provision_session", new_callable=AsyncMock) as provision:
                with self.assertRaises(LoginSetupError) as raised:
                    await _run(args)
                self.assertEqual(raised.exception.code, "interactive_tty_required")
                provision.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
