"""Fake-only password transport probe: actual CLI, controlling PTY, no network."""
import argparse
import json

from pty_login_driver import command_for, run_pty


CHILD = r'''
import hashlib, json, socket, sys, tempfile, termios
from pathlib import Path
from types import SimpleNamespace
def no_network(*args, **kwargs):
    raise AssertionError("network forbidden in password PTY test")
socket.socket.connect = no_network
socket.socket.connect_ex = no_network
socket.create_connection = no_network
import telethon
from telethon.errors import SessionPasswordNeededError
import telegram_assistant.telegram_login as helper
expected = EXPECTED_PLACEHOLDER
received = []
class FakeClient:
    def __init__(self, path, api_id, api_hash, **kwargs):
        self.path = Path(path + ".session")
        self.authorized = False
    async def connect(self):
        pass
    async def is_user_authorized(self):
        return self.authorized
    async def send_code_request(self, phone):
        return SimpleNamespace(phone_code_hash="fake-only")
    async def sign_in(self, **kwargs):
        if "password" not in kwargs:
            raise SessionPasswordNeededError(None)
        received.append(kwargs["password"])
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
    helper._save_private_config(config / "login.json", json.dumps(dict(version=1,
        api_id=12345, api_hash="a"*32, phone="+15555550100")).encode())
    sys.argv = ["telegram-login", "--config-dir", str(config), "--session-dir", str(session)]
    flags = termios.tcgetattr(0)
    assert helper.main() == 0
    assert termios.tcgetattr(0) == flags
    assert len(received) == 1
    print("PASSWORD_EXACT=" + str(received[0] == expected), flush=True)
    print("PASTE_FRAMING_REACHED_CLIENT=" + str("\x1b[200~" in received[0] or "\x1b[201~" in received[0]), flush=True)
    assert expected not in (config / "login.json").read_text()
    assert expected not in (config / "telegram.json").read_text()
'''


CASES = (
    ("ASCII-specials", "fake_$`\\!@#%&'\"()[]{}", None),
    ("edge-spaces", "  fake-pass with spaces  ", None),
    ("Unicode", "фиктивный_秘密_🙂", None),
    ("NFD-preserved", "fake_Cafe\u0301_🙂", None),
    ("UTF8-backspace", "fake_after_erase", "С🙂".encode() + b"\x7f\x7f" + b"fake_after_erase"),
    ("bracketed-paste", "fake_pasted_password", b"\x1b[200~fake_pasted_password\x1b[201~"),
    ("pasted-edge-spaces", "  fake_pasted_spaces  ", b"\x1b[200~  fake_pasted_spaces  \x1b[201~"),
)


def probe(case, *, image=None, answers=None):
    name, expected, typed = case
    command = command_for(image)
    command[-1] = CHILD.replace("EXPECTED_PLACEHOLDER", repr(expected))
    steps = [(b"Type CHECK (or CANCEL): ", b"CHECK"),
             (b"Type SEND (or CANCEL): ", b"SEND"),
             (b"login code (hidden): ", b"98765")]
    steps += [(b"password (hidden; Enter to stop): ", answer)
              for answer in (answers or (typed if typed is not None else expected.encode(),))]
    status, output = run_pty(command, steps_override=steps, timeout=30)
    assert status == 0, "fake-only CLI failed"
    assert expected.encode() not in output, "fake password was echoed"
    return b"PASSWORD_EXACT=True" in output, output


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image")
    parser.add_argument("--expect-paste-defect", action="store_true")
    args = parser.parse_args()
    for case in CASES:
        exact, output = probe(case, image=args.image)
        expected_exact = not (args.expect_paste_defect and "paste" in case[0])
        assert exact == expected_exact, "unexpected fake transport result: " + case[0]
        framing = b"PASTE_FRAMING_REACHED_CLIENT=True" in output
        print(case[0] + " exact=" + str(exact) + " framing_reached_client=" + str(framing))
    source = next(line for line in output.decode().splitlines() if line.startswith("SOURCE_SHA256="))
    print(source)
    print("network_none_fake_inputs_no_private_mounts")
