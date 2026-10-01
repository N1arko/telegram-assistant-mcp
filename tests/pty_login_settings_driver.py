"""Full CLI: configure without networking, reject fake OTP, reuse settings.

Run on the actual Linux image with network=none and no private mounts.
Every field and session is synthetic and lives only in container tmpfs.
"""
import argparse

from pty_login_driver import command_for, run_pty


CHILD = r'''
import hashlib, json, socket, sys, tempfile, termios
from pathlib import Path
from types import SimpleNamespace
def forbidden_network(*args, **kwargs):
    raise AssertionError("network forbidden in fake CLI test")
socket.socket.connect = forbidden_network
socket.socket.connect_ex = forbidden_network
socket.create_connection = forbidden_network
import telethon
from telethon.errors import PhoneCodeInvalidError
import telegram_assistant.telegram_login as helper
attempts = 0
class FakeClient:
    def __init__(self, path, api_id, api_hash, **kwargs):
        global attempts
        attempts += 1
        assert api_id == 12345 and api_hash == "a" * 32
        self.path = Path(path + ".session")
        self.authorized = False
    async def connect(self):
        self.path.write_bytes(b"fake-only-incomplete-session")
    async def is_user_authorized(self):
        return self.authorized
    async def send_code_request(self, phone):
        assert phone == "+15555550100"
        return SimpleNamespace(phone_code_hash="fake-only")
    async def sign_in(self, **kwargs):
        assert kwargs.get("code") == "98765" and "password" not in kwargs
        if attempts == 1:
            raise PhoneCodeInvalidError(None)
        self.path.write_bytes(b"fake-only-authorized-session")
        self.authorized = True
    async def disconnect(self):
        pass
telethon.TelegramClient = FakeClient
print("SOURCE_SHA256=" + hashlib.sha256(Path(helper.__file__).read_bytes()).hexdigest(), flush=True)
with tempfile.TemporaryDirectory() as root:
    root = Path(root).resolve()
    config, session = root / "config", root / "session"
    config.mkdir(mode=0o700)
    session.mkdir(mode=0o700)
    argv = ["telegram-login", "--config-dir", str(config), "--session-dir", str(session)]
    flags = termios.tcgetattr(0)
    sys.argv = argv + ["--configure-login"]
    assert helper.main() == 0 and attempts == 0
    saved = config / "login.json"
    first = saved.read_bytes()
    assert saved.stat().st_mode & 0o777 == 0o600
    assert json.loads(first)["phone"] == "+15555550100"
    print("CONFIGURE_NO_CLIENT_PASS", flush=True)
    sys.argv = argv
    assert helper.main() == 1 and attempts == 1
    assert saved.read_bytes() == first and not list(session.iterdir())
    print("FAILED_CODE_SETTINGS_RETAINED_PASS", flush=True)
    assert helper.main() == 0 and attempts == 2
    assert saved.read_bytes() == first and b"98765" not in first
    assert termios.tcgetattr(0) == flags
    print("RETRY_NO_CREDENTIAL_PROMPTS_PASS", flush=True)
    print("TTY_FLAGS_RESTORED", flush=True)
'''


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image")
    args = parser.parse_args()
    command = command_for(args.image)
    command[-1] = CHILD
    steps = [
        (b"Type CHECK (or CANCEL): ", b"CHECK"),
        (b"API ID (hidden): ", b"12345"),
        (b"API hash (hidden): ", b"a" * 32),
        (b"E.164 format (hidden): ", b"+15555550100"),
    ]
    for _ in range(2):
        steps += [
            (b"Type CHECK (or CANCEL): ", b"CHECK"),
            (b"Type SEND (or CANCEL): ", b"SEND"),
            (b"login code (hidden): ", b"98765"),
        ]
    code, output = run_pty(command, steps_override=steps, timeout=30)
    assert code == 0, "fake-only CLI transcript=" + repr(output)
    for marker in (b"CONFIGURE_NO_CLIENT_PASS", b"FAILED_CODE_SETTINGS_RETAINED_PASS",
                   b"RETRY_NO_CREDENTIAL_PROMPTS_PASS", b"TTY_FLAGS_RESTORED"):
        assert marker in output
    for field in (b"API ID (hidden): ", b"API hash (hidden): ", b"E.164 format (hidden): "):
        assert output.count(field) == 1
    assert b"telegram_code_invalid" in output
    assert b"two-step verification password (hidden" not in output
    for secret in (b"a" * 32, b"+15555550100", b"98765"):
        assert secret not in output
    source = next(line for line in output.decode().splitlines() if line.startswith("SOURCE_SHA256="))
    print(source)
    print("PASS actual CLI configure + failed OTP + retry; credentials prompted once; mode 0600; no password prompt; no network/private mounts")
