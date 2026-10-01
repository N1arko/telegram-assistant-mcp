"""Exercise the actual login CLI in a controlling PTY, using fake inputs only.

Optional --image runs the same path through docker run -it, with network=none
and no host/private mounts. No real Telegram call is possible.
"""
import argparse
import json
import os
import pty
import select
import signal
import subprocess
import sys
import tempfile
import time


CHILD = r'''
import builtins, hashlib, os, socket, tempfile, termios
from pathlib import Path
from types import SimpleNamespace
def no_network(*args, **kwargs):
    raise AssertionError("network forbidden in PTY test")
socket.socket.connect = no_network
socket.socket.connect_ex = no_network
socket.create_connection = no_network
import telethon
import telegram_assistant.telegram_login as helper
class FakeClient:
    def __init__(self, path, api_id, api_hash, **kwargs):
        assert api_id == 12345 and api_hash == "a" * 32
        self.path = Path(path + ".session")
        self.authorized = False
    async def connect(self):
        print("MOCK_CONNECT", flush=True)
    async def is_user_authorized(self):
        return self.authorized
    async def send_code_request(self, phone):
        assert phone == "+15555550100"
        print("MOCK_CODE_REQUEST", flush=True)
        return SimpleNamespace(phone_code_hash="mock-only")
    async def sign_in(self, **kwargs):
        assert kwargs.get("code") == "12345"
        self.path.write_bytes(b"mock-session-only")
        self.authorized = True
    async def disconnect(self):
        pass
telethon.TelegramClient = FakeClient
original_input = builtins.input
def observed_input(prompt):
    value = original_input(prompt)
    print("CONFIRM_SHAPE length=%d ascii=%s empty=%s" %
          (len(value), value.isascii(), not value), flush=True)
    return value
helper.input = observed_input
with tempfile.TemporaryDirectory() as root:
    root = Path(root).resolve()
    config, session = root / "config", root / "session"
    config.mkdir(mode=0o700)
    session.mkdir(mode=0o700)
    sys_argv = ["telegram-login", "--config-dir", str(config), "--session-dir", str(session)]
    import sys
    sys.argv = sys_argv
    print("SOURCE_SHA256=" + hashlib.sha256(Path(helper.__file__).read_bytes()).hexdigest(), flush=True)
    flags = termios.tcgetattr(0)
    result = helper.main()
    assert termios.tcgetattr(0) == flags, "terminal flags were not restored"
    print("TTY_FLAGS_RESTORED", flush=True)
    raise SystemExit(result)
'''


def run_pty(command, *, suffix=b"\n", confirmation=b"SEND", preflight=False,
            preflight_answers=(b"CHECK",), field_prefix=b"", field_answers=None,
            steps_override=None, timeout=15):
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(command[0], command)
    steps = [(b"Type CHECK (or CANCEL): ", value) for value in preflight_answers] if preflight else []
    fields = [
        (b"API ID (hidden): ", b"12345"),
        (b"API hash (hidden): ", b"a" * 32),
        (b"E.164 format (hidden): ", b"+15555550100"),
    ]
    for marker, default in fields:
        answers = (field_answers or {}).get(marker, (default,))
        steps += [(marker, field_prefix + answer) for answer in answers]
    values = confirmation if isinstance(confirmation, tuple) else (confirmation,)
    marker = b"Type SEND (or CANCEL): " if preflight else b"Type SEND: "
    steps += [(marker, value) for value in values]
    steps.append((b"login code (hidden): ", field_prefix + b"12345"))
    if steps_override is not None:
        steps = list(steps_override)
    transcript = b""
    cursor = 0
    deadline = time.monotonic() + timeout
    status = None
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.05)
            if ready:
                try:
                    data = os.read(fd, 8192)
                except OSError:
                    break
                if not data:
                    break
                transcript += data
                if steps:
                    marker, answer = steps[0]
                    found = transcript.find(marker, cursor)
                    if found >= 0:
                        cursor = found + len(marker)
                        steps.pop(0)
                        os.write(fd, answer + suffix)
            waited, status = os.waitpid(pid, os.WNOHANG)
            if waited:
                break
        else:
            os.kill(pid, signal.SIGKILL)
            raise AssertionError("PTY test timed out; fake-only transcript=" + repr(transcript))
        if status is None or waited == 0:
            _, status = os.waitpid(pid, 0)
    finally:
        os.close(fd)
    return os.waitstatus_to_exitcode(status), transcript


def command_for(image=None):
    if not image:
        return [sys.executable, "-u", "-c", CHILD]
    return [
        "docker", "run", "--rm", "-it", "--network", "none", "--read-only",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "10001:10001", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,mode=1777",
        "--entrypoint", "python", image, "-c", CHILD,
    ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image")
    parser.add_argument("--compose", help="Use the deployed service settings, stripped of private mounts/network")
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    sandbox_file = None
    command = command_for(args.image)
    if args.compose:
        original = json.loads(subprocess.check_output([
            "docker", "compose", "-f", args.compose, "--profile", "login", "config", "--format", "json",
        ]))
        service = original["services"]["telegram-login"]
        for key in ("build", "volumes", "networks", "profiles", "depends_on"):
            service.pop(key, None)
        service.update(network_mode="none", entrypoint=["python", "-c", CHILD], command=[],
                       tmpfs=["/tmp:rw,noexec,nosuid,size=16m,mode=1777"], pull_policy="never")
        sandbox_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json")
        json.dump({"name": "telegram-assistant-pty-check", "services": {"telegram-login": service}}, sandbox_file)
        sandbox_file.flush()
        command = ["docker", "compose", "-f", sandbox_file.name, "run", "--rm", "-it", "--no-deps", "telegram-login"]
    cases = [
        ("LF", b"\n", b"SEND", (b"CHECK",), 0),
        ("CR", b"\r", b"SEND", (b"CHECK",), 0),
        ("CRLF", b"\r\n", b"SEND", (b"CHECK",), 0),
        ("paste", b"\n", b"\x1b[200~SEND\x1b[201~", (b"CHECK",), 0),
    ]
    if args.preflight:
        cases += [
            ("retry", b"\n", (b"", "SЕND".encode(), b"SEND"),
             (b"", "CHЕCK".encode(), b"CHECK"), 0),
            ("cancel", b"\n", b"CANCEL", (b"CHECK",), 1),
        ]
    for name, suffix, confirmation, preflight_answers, expected in cases:
        status, transcript = run_pty(command, suffix=suffix, confirmation=confirmation,
                                     preflight=args.preflight, preflight_answers=preflight_answers)
        assert status == expected, (name, status, transcript)
        assert (b"MOCK_CODE_REQUEST" in transcript) == (expected == 0), (name, transcript)
        assert b"TTY_FLAGS_RESTORED" in transcript, (name, transcript)
        assert b"a" * 32 not in transcript and b"+15555550100" not in transcript, (name, transcript)
        source = next(line for line in transcript.decode("utf-8", errors="replace").splitlines() if line.startswith("SOURCE_SHA256="))
        print(name, "PASS", source, "private_inputs_echoed=false", flush=True)
    if args.preflight:
        edited = bytes.fromhex("d0a1") + b"\x7f"
        for name, pref, confirms, field_prefix, field_answers in (
            ("UTF8-edit", (edited + b"CHECK",), edited + b"SEND", edited, None),
            ("invalid-UTF8-retry", (b"\xffCHECK", b"CHECK"), (b"\xffSEND", b"SEND"), b"",
             {b"API ID (hidden): ": (b"\xff12345", b"12345")}),
        ):
            status, transcript = run_pty(command, preflight=True, preflight_answers=pref,
                                         confirmation=confirms, field_prefix=field_prefix,
                                         field_answers=field_answers)
            assert status == 0 and b"MOCK_CODE_REQUEST" in transcript, (name, status, transcript)
            assert b"TTY_FLAGS_RESTORED" in transcript, (name, transcript)
            assert b"a" * 32 not in transcript and b"+15555550100" not in transcript, (name, transcript)
            print(name, "PASS", "private_inputs_echoed=false", flush=True)
    if sandbox_file:
        sandbox_file.close()
