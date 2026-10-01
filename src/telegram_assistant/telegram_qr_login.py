"""User-operated QR provisioning for the dedicated Telegram session only.

No phone-code/password fallback. QR/token goes exclusively to /dev/tty in an
alternate screen, never stdout/stderr, files, arguments or logs.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
from datetime import datetime, timezone
import fcntl
import io
import json
import logging
import math
import os
from pathlib import Path
import re
import signal
import stat
import sys
import termios

from .telegram_login import (
    LoginSetupError, _TTYConsole, _load_login_settings, _remove_incomplete_session,
    _request_confirmation, _safe_login_failure, _save_private_config, _secure_directory,
)


@contextlib.contextmanager
def _provision_lock(config_dir):
    try:
        fd = os.open(config_dir / '.qr-provision.lock',
                     os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    except OSError:
        raise LoginSetupError('unsafe_provision_lock') from None
    try:
        s = os.fstat(fd)
        if (not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or
                stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1):
            raise LoginSetupError('unsafe_provision_lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LoginSetupError('provision_already_running') from None
        yield
    finally:
        os.close(fd)


def _sync_private_session(path):
    """Commit/close is handled by the SDK; fsync durable private files here."""
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.geteuid() or s.st_nlink != 1:
            raise LoginSetupError('unsafe_new_session')
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _qr_lifetime(qr):
    expires = qr.expires
    if not isinstance(expires, datetime) or expires.utcoffset() is None:
        raise LoginSetupError('telegram_qr_invalid_expiry')
    remaining = (expires - datetime.now(timezone.utc)).total_seconds()
    if remaining <= 0:
        raise LoginSetupError('telegram_qr_expired')
    if remaining > 120:
        raise LoginSetupError('telegram_qr_invalid_expiry')
    return remaining


@contextlib.contextmanager
def _display_qr(fd, uri, seconds):
    """Only balanced private-TTY screen state; never emit the token URI."""
    if not os.isatty(fd):
        raise LoginSetupError('qr_display_tty_required')
    if not isinstance(uri, str) or not re.fullmatch(r'tg://login\?token=[A-Za-z0-9_-]{8,172}', uri):
        raise LoginSetupError('telegram_qr_invalid_token')
    import qrcode
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4)
    qr.add_data(uri)
    qr.make(fit=True)
    width = qr.modules_count + 8
    rows, cols = termios.tcgetwinsize(fd)
    if cols < width or rows < math.ceil(width / 2) + 5:
        raise LoginSetupError('qr_terminal_too_small')
    # Render to memory first so failure cannot leave a partial sensitive screen.
    class TTYBuffer(io.StringIO):
        def isatty(self):
            return True
    output = TTYBuffer()
    qr.print_ascii(out=output, tty=True)
    screen = output.getvalue()
    old = termios.tcgetattr(fd)
    new = old.copy()
    new[3] &= ~(termios.ECHO | termios.ECHONL)
    try:
        termios.tcsetattr(fd, termios.TCSAFLUSH, new)
        os.write(fd, b'\x1b[?1049h\x1b[2J\x1b[H')
        os.write(fd, ('Scan in Telegram > Settings > Devices > Link Device.\n'
                      'Select the intended account. Ctrl+C cancels.\n'
                      f'Expires within {math.ceil(seconds)} seconds; no automatic refresh.\n').encode())
        data = screen.encode('utf-8')
        while data:
            data = data[os.write(fd, data):]
        yield
    finally:
        try:
            os.write(fd, b'\x1b[2J\x1b[H\x1b[?1049l')
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)


async def provision_qr_session(*, config_dir, session_dir, confirm_prompt, display_qr,
                               client_factory=None, timeout=30):
    config_dir = _secure_directory(Path(config_dir))
    session_dir = _secure_directory(Path(session_dir))
    with _provision_lock(config_dir):
        return await _provision_qr_session(config_dir, session_dir, confirm_prompt,
                                           display_qr, client_factory, timeout)


async def _provision_qr_session(config_dir, session_dir, confirm_prompt, display_qr,
                                 client_factory, timeout):
    config_path, session_path = config_dir / 'telegram.json', session_dir / 'assistant.session'
    if any(p.exists() or p.is_symlink() for p in (config_path, session_path)):
        raise LoginSetupError('target_already_exists')
    if not (config_dir / 'login.json').exists():
        raise LoginSetupError('login_settings_required')
    api_id, api_hash, phone = _load_login_settings(config_dir / 'login.json')
    print('Saved API ID/hash/phone loaded privately. QR mode never asks for a password.',
          file=sys.stderr, flush=True)
    _request_confirmation(
        f'Create one QR login for the account ending {phone[-4:]}? Type QR (or CANCEL): ',
        confirm_prompt, 'QR')
    client, wait_task = None, None
    authenticated, disconnected = False, False
    phase = 'qr_client_setup'
    try:
        from telethon.errors import SessionPasswordNeededError
        if client_factory is None:
            from telethon import TelegramClient
            client_factory = TelegramClient
        client = client_factory(str(session_path.with_suffix('')), api_id, api_hash,
            receive_updates=True, flood_sleep_threshold=0, request_retries=0,
            connection_retries=1, raise_last_call_error=True)
        phase = 'qr_connect'
        await asyncio.wait_for(client.connect(), timeout)
        phase = 'qr_authorization_check'
        if await asyncio.wait_for(client.is_user_authorized(), timeout):
            raise LoginSetupError('target_already_authorized')
        phase = 'qr_export'
        qr = await asyncio.wait_for(client.qr_login(), timeout)
        lifetime = _qr_lifetime(qr)
        async def wait_and_commit():
            nonlocal authenticated
            user = await qr.wait(timeout=lifetime)
            # Capture success before the parent task can be cancelled/verification
            # can fail. Never discard an already authorized session on error.
            authenticated = True
            client.session.save()
            return user
        wait_task = asyncio.create_task(wait_and_commit())
        await asyncio.sleep(0)  # SDK's UpdateLoginToken handler precedes display.
        phase = 'qr_wait'
        with display_qr(qr.url, lifetime):
            try:
                user = await wait_task
            except SessionPasswordNeededError:
                raise LoginSetupError('telegram_qr_password_required') from None
            except asyncio.TimeoutError:
                raise LoginSetupError('telegram_qr_expired') from None
        phase = 'qr_verify_account'
        actual_phone = getattr(user, 'phone', None)
        if (type(getattr(user, 'id', None)) is not int or user.id <= 0 or
                getattr(user, 'bot', False) or not isinstance(actual_phone, str) or
                not re.fullmatch(r'\+?[1-9][0-9]{6,14}', actual_phone)):
            raise LoginSetupError('telegram_qr_account_unverifiable')
        if actual_phone.lstrip('+') != phone[1:]:
            raise LoginSetupError('telegram_qr_account_mismatch')
        phase = 'qr_disconnect'
        await asyncio.wait_for(client.disconnect(), min(timeout, 10))
        disconnected = True
        phase = 'qr_save_session'
        _sync_private_session(session_path)
        _save_private_config(config_path, (json.dumps(dict(api_id=api_id, api_hash=api_hash,
            session_file=str(session_path)), separators=(',', ':')) + '\n').encode())
        return config_path, session_path
    except LoginSetupError:
        raise
    except Exception as exc:
        raise _safe_login_failure(exc, phase) from None
    finally:
        if wait_task is not None and not wait_task.done():
            wait_task.cancel()
            with contextlib.suppress(BaseException):
                await wait_task
        if client is not None and not disconnected:
            with contextlib.suppress(BaseException):
                await asyncio.wait_for(client.disconnect(), min(timeout, 10))
        if authenticated:
            # Retain/quarantine an authorized session even if account verification,
            # disconnect or config write failed; no runtime config means no reader.
            with contextlib.suppress(Exception):
                _sync_private_session(session_path)
        else:
            _remove_incomplete_session(session_path)


async def _run(args):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise LoginSetupError('interactive_tty_required')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    with _TTYConsole() as console:
        _request_confirmation('Terminal check; no account data or network. Type CHECK (or CANCEL): ',
                              console.confirmation, 'CHECK')
        print('Terminal check passed.', file=sys.stderr, flush=True)
        await provision_qr_session(config_dir=args.config_dir, session_dir=args.session_dir,
            confirm_prompt=console.confirmation,
            display_qr=lambda uri, seconds: _display_qr(console.fd, uri, seconds))


def main():
    parser = argparse.ArgumentParser(description='User-operated dedicated Telegram QR login; no 2FA fallback')
    parser.add_argument('--config-dir', type=Path, default=Path('/run/telegram'))
    parser.add_argument('--session-dir', type=Path, default=Path('/sessions'))
    args = parser.parse_args()
    def terminate(_signal, _frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        asyncio.run(_run(args))
        print('Telegram session and private config saved. No MCP service was started.')
        return 0
    except KeyboardInterrupt:
        print('telegram_qr_login: cancelled', file=sys.stderr)
        return 130
    except LoginSetupError as exc:
        print(f'telegram_qr_login: setup_failed ({exc.code})', file=sys.stderr)
        if exc.code == 'telegram_qr_password_required':
            print('Telegram also requires the cloud password for QR login. Stopped without '
                  'asking for a password; do not repeat the same login attempt.', file=sys.stderr)
        elif exc.code == 'qr_terminal_too_small':
            print('Resize the terminal to at least 80 columns and 40 rows before a new manual attempt.',
                  file=sys.stderr)
        elif exc.code in {'telegram_qr_account_mismatch', 'telegram_qr_account_unverifiable',
                          'private_config_write_failed'} or exc.code.startswith('telegram_failed_qr_'):
            print('An authorized session may exist. Live reader is disabled; contact the operator '
                  'before rerunning or moving any files.', file=sys.stderr)
        if exc.retry_after_seconds is not None:
            print(f'Retry no sooner than {exc.retry_after_seconds} seconds; no automatic retry.', file=sys.stderr)
        return 1
    except Exception:
        print('telegram_qr_login: setup_failed (internal_error)', file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    raise SystemExit(main())
