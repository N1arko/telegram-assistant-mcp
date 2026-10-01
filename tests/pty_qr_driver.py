"""Actual QR CLI + private TTY renderer, fake token/auth, network forbidden."""
import argparse
from pathlib import Path
import sys

from pty_login_driver import command_for, run_pty


CHILD = r'''
import contextlib, io, json, os, socket, sys, tempfile, termios
from pathlib import Path
sys.path.insert(0, TESTS_PLACEHOLDER)
def no_network(*args, **kwargs):
    raise AssertionError("network forbidden in fake QR test")
socket.socket.connect = no_network
socket.socket.connect_ex = no_network
socket.create_connection = no_network
import telethon
from telethon.errors import SessionPasswordNeededError
from telegram_assistant.telegram_login import _save_private_config
import telegram_assistant.telegram_qr_login as helper
from test_telegram_qr_login import FakeClient, FakeQR, FAKE_URI, PHONE
mode = MODE_PLACEHOLDER
clients = []
def factory(*args, **kwargs):
    client = FakeClient(*args, **kwargs)
    if mode == '2fa':
        client.qr = FakeQR(client, error=SessionPasswordNeededError(None))
    elif mode == 'expired':
        client.qr = FakeQR(client, expiry=-1)
    clients.append(client)
    return client
telethon.TelegramClient = factory
original = helper._display_qr
@contextlib.contextmanager
def display(fd, uri, seconds):
    assert clients[0].qr.started.is_set(), "listener must precede display"
    with original(fd, uri, seconds):
        if mode != 'cancel':
            clients[0].qr.approved.set()
        yield
helper._display_qr = display
class CapturedTTY(io.StringIO):
    def isatty(self):
        return True
termios.tcsetwinsize(0, (10,20) if mode=='small' else (45,100))
flags = termios.tcgetattr(0)
with tempfile.TemporaryDirectory() as root:
    root = Path(root).resolve()
    config, session = root/'config', root/'session'
    config.mkdir(mode=0o700)
    session.mkdir(mode=0o700)
    _save_private_config(config/'login.json', json.dumps(dict(version=1, api_id=12345,
                                  api_hash='a'*32, phone=PHONE)).encode())
    before = (config/'login.json').read_bytes()
    sys.argv = ['telegram-qr-login','--config-dir',str(config),'--session-dir',str(session)]
    stdout, stderr = CapturedTTY(), CapturedTTY()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        result = helper.main()
    assert termios.tcgetattr(0) == flags
    assert (config/'login.json').read_bytes() == before
    for captured in (stdout.getvalue(), stderr.getvalue()):
        assert FAKE_URI not in captured and 'a'*32 not in captured and PHONE not in captured
        assert 'password (hidden' not in captured
    if mode=='success':
        assert result==0
        for target in (config/'telegram.json',session/'assistant.session'):
            assert target.stat().st_mode & 0o777 == 0o600
        assert clients[0].exports==1
    else:
        assert result == (130 if mode=='cancel' else 1)
        assert not (config/'telegram.json').exists() and not list(session.iterdir())
        expected = {'2fa':'telegram_qr_password_required','expired':'telegram_qr_expired',
                    'small':'qr_terminal_too_small','consent':'cancelled','cancel':'cancelled'}[mode]
        assert expected in stderr.getvalue()
        assert len(clients)==(0 if mode=='consent' else 1)
        if clients:
            assert clients[0].exports==1
    print('QR_MOCK_RESULT_PASS',flush=True)
    print('PRIVATE_STDIO_NO_TOKEN_SETTINGS_INTACT_TTY_RESTORED',flush=True)
'''


def probe(mode, *, image=None, tests_dir=None):
    tests_dir = tests_dir or str(Path(__file__).parent.resolve())
    child = CHILD.replace('TESTS_PLACEHOLDER', repr('/tests' if image else tests_dir)).replace('MODE_PLACEHOLDER',repr(mode))
    command = command_for(image)
    if image:
        # Only own synthetic test code is mounted, never production private paths.
        command[2:2] = ['--mount',f'type=bind,src={tests_dir},dst=/tests,readonly']
    command[-1] = child
    steps = [(b'Type CHECK (or CANCEL): ',b'CHECK'),
             (b'Type QR (or CANCEL): ',b'CANCEL' if mode=='consent' else b'QR')]
    if mode=='cancel':
        steps.append((b'Expires within',b'\x03'))
    code, output = run_pty(command, steps_override=steps, timeout=30)
    assert code==0 and b'QR_MOCK_RESULT_PASS' in output, 'fake QR CLI check failed: '+mode
    assert b'tg://login?token=' not in output
    assert b'Telegram API ID' not in output and b'password (hidden' not in output
    if mode in ('success','2fa','cancel'):
        assert b'\x1b[?1049h' in output and b'\x1b[?1049l' in output
    return output


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--image')
    args=parser.parse_args()
    for mode in ('success','2fa','expired','small','consent','cancel'):
        probe(mode,image=args.image)
        print(mode+' PASS private TTY, no token in stdio, settings intact, no network')
