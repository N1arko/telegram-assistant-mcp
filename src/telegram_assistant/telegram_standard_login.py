"""One user-operated stock Telethon/getpass attempt; no custom terminal reader."""
from __future__ import annotations

import argparse
import asyncio
import contextlib
from dataclasses import dataclass
import getpass
import io
import json
import logging
import os
from pathlib import Path
import re
import signal
import sys
import warnings

from telethon import TelegramClient, functions, types

from .telegram_login import (
    LoginSetupError, _load_login_settings, _remove_incomplete_session,
    _request_confirmation, _safe_login_failure, _save_private_config, _secure_directory,
)
from .telegram_qr_login import _provision_lock, _sync_private_session


@dataclass
class ProbeState:
    accepted: bool = False
    last_rpc: str = 'none'
    failure: LoginSetupError | None = None
    dc_changed: bool = False


class _DiscardOutput(io.TextIOBase):
    def write(self, value):
        return len(value)
    def flush(self):
        pass


def _stock_secret(prompt):
    # Standard getpass only. A warning aborts before its echoing fallback reads.
    with warnings.catch_warnings():
        warnings.simplefilter('error', getpass.GetPassWarning)
        try:
            return getpass.getpass(prompt)
        except (getpass.GetPassWarning, EOFError, UnicodeError, OSError):
            raise LoginSetupError('standard_terminal_input_failed') from None


class _ProbeClient(TelegramClient):
    def __init__(self, *args, probe_state, probe_timeout=30, **kwargs):
        super().__init__(*args, **kwargs)
        self.probe_state = probe_state
        self._probe_timeout = probe_timeout
        self._probe_counts = {}

    async def connect(self):
        return await asyncio.wait_for(super().connect(), self._probe_timeout)

    async def __call__(self, request, *args, **kwargs):
        names = {
            functions.auth.SendCodeRequest: 'send_code',
            functions.auth.SignInRequest: 'sign_in_code',
            functions.account.GetPasswordRequest: 'get_password',
            functions.auth.CheckPasswordRequest: 'check_password',
            functions.users.GetUsersRequest: 'get_self',
            functions.updates.GetStateRequest: 'get_state',
            functions.updates.GetDifferenceRequest: 'get_difference',
        }
        phase = names.get(type(request), 'other_rpc')
        state = self.probe_state
        state.last_rpc, state.failure = phase, None
        # Also stop SDK-internal AuthRestart/resend paths, independent of
        # max_attempts. Never repeat a login request without fresh human consent.
        if phase in {'send_code', 'sign_in_code', 'get_password', 'check_password'}:
            if self._probe_counts.get(phase, 0):
                raise LoginSetupError('standard_attempt_limit')
            self._probe_counts[phase] = 1
        before_dc = self.session.dc_id
        try:
            result = await asyncio.wait_for(super().__call__(request, *args, **kwargs), self._probe_timeout)
            if (phase in {'sign_in_code', 'check_password'} and
                    isinstance(result, types.auth.Authorization)):
                # SDK _on_login runs later and may fail in an updates RPC.
                # Capture acceptance and commit before that; retain on failure.
                state.accepted = True
                self.session.save()
            return result
        except LoginSetupError:
            raise
        except Exception as exc:
            state.last_rpc = phase
            state.failure = _safe_login_failure(exc, phase)
            raise
        finally:
            state.dc_changed |= self.session.dc_id != before_dc


async def provision_standard_session(*, config_dir, session_dir, state=None,
                                     confirm_prompt=input, secret_prompt=_stock_secret,
                                     client_factory=None, timeout=30):
    state = state if state is not None else ProbeState()
    config_dir = _secure_directory(Path(config_dir))
    session_dir = _secure_directory(Path(session_dir))
    config_path = config_dir / 'telegram.json'
    session_path = session_dir / 'assistant.session'
    with _provision_lock(config_dir):
        if any(p.exists() or p.is_symlink() for p in (config_path, session_path)):
            raise LoginSetupError('target_already_exists')
        if not (config_dir / 'login.json').exists():
            raise LoginSetupError('login_settings_required')
        api_id, api_hash, phone = _load_login_settings(config_dir / 'login.json')
        _request_confirmation(
            'Standard Telethon/getpass: request one login code using saved settings? '
            'Type SEND (or CANCEL): ', confirm_prompt, 'SEND')
        client, disconnected = None, False
        phase = 'standard_client_setup'
        code_asked, password_asked = False, False
        def code_callback():
            nonlocal phase, code_asked
            if code_asked:
                raise LoginSetupError('standard_attempt_limit')
            phase, code_asked = 'code_prompt', True
            value = secret_prompt('Telegram login code (hidden): ')
            if not re.fullmatch(r'[0-9]{4,8}', value):
                raise LoginSetupError('invalid_login_code')
            phase = 'sign_in_code'
            return value
        def password_callback():
            nonlocal phase, password_asked
            if password_asked:
                raise LoginSetupError('standard_attempt_limit')
            phase, password_asked = 'password_prompt', True
            value = secret_prompt('Telegram cloud password (hidden; Enter cancels): ')
            if not value:
                raise LoginSetupError('cancelled')
            phase = 'sign_in_password'
            return value  # No strip/framing/case/Unicode transformations.
        try:
            if client_factory is None:
                client_factory = _ProbeClient
            client = client_factory(str(session_path.with_suffix('')), api_id, api_hash,
                probe_state=state, probe_timeout=timeout, receive_updates=False, flood_sleep_threshold=0,
                request_retries=0, connection_retries=1, raise_last_call_error=True)
            # No SDK account/name/error output is retained, even in memory logs.
            # getpass opens /dev/tty itself; its prompts bypass this discard sink.
            with contextlib.redirect_stdout(_DiscardOutput()), contextlib.redirect_stderr(_DiscardOutput()):
                phase = 'standard_start'
                # Bound individual network operations, not the human's input time.
                await client.start(phone=phone, max_attempts=1,
                    code_callback=code_callback, password=password_callback)
                if not state.accepted:
                    raise LoginSetupError('target_already_authorized')
                phase = 'standard_verify_account'
                user = await asyncio.wait_for(client.get_me(), timeout)
                actual_phone = getattr(user, 'phone', None)
                if (type(getattr(user, 'id', None)) is not int or user.id <= 0 or
                        getattr(user, 'bot', False) or not isinstance(actual_phone, str) or
                        not re.fullmatch(r'\+?[1-9][0-9]{6,14}', actual_phone)):
                    raise LoginSetupError('standard_account_unverifiable')
                if actual_phone.lstrip('+') != phone[1:]:
                    raise LoginSetupError('standard_account_mismatch')
                phase = 'standard_disconnect'
                await asyncio.wait_for(client.disconnect(), min(timeout, 10))
                disconnected = True
            phase = 'standard_save_session'
            _sync_private_session(session_path)
            _save_private_config(config_path, (json.dumps(dict(api_id=api_id, api_hash=api_hash,
                session_file=str(session_path)), separators=(',', ':')) + '\n').encode())
            return config_path, session_path
        except LoginSetupError:
            raise
        except Exception as exc:
            # start() rewrites some RPC failures. Preserve only our fixed safe
            # mapping from the actual failing RPC, never its raw exception.
            if phase not in {'code_prompt', 'password_prompt'} and state.failure is not None:
                raise state.failure from None
            raise _safe_login_failure(exc, phase) from None
        finally:
            if client is not None and not disconnected:
                with contextlib.suppress(BaseException):
                    await asyncio.wait_for(client.disconnect(), min(timeout, 10))
            if state.accepted:
                with contextlib.suppress(Exception):
                    _sync_private_session(session_path)
            else:
                _remove_incomplete_session(session_path)


async def _run(args, state):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise LoginSetupError('interactive_tty_required')
    os.umask(0o077)
    logging.disable(logging.CRITICAL)
    await provision_standard_session(config_dir=args.config_dir,
        session_dir=args.session_dir, state=state)


def main():
    parser = argparse.ArgumentParser(description='One stock Telethon/getpass login attempt')
    parser.add_argument('--config-dir', type=Path, default=Path('/run/telegram'))
    parser.add_argument('--session-dir', type=Path, default=Path('/sessions'))
    args, state = parser.parse_args(), ProbeState()
    def terminate(_signal, _frame):
        raise KeyboardInterrupt
    previous = signal.signal(signal.SIGTERM, terminate)
    try:
        asyncio.run(_run(args, state))
        print('Telegram session and private config saved. No MCP service was started.')
        return 0
    except KeyboardInterrupt:
        print('telegram_standard_login: cancelled', file=sys.stderr)
        return 130
    except LoginSetupError as exc:
        print(f'telegram_standard_login: setup_failed ({exc.code})', file=sys.stderr)
        if state.last_rpc != 'none':
            print(f'standard_probe_rpc: {state.last_rpc}', file=sys.stderr)
            print('standard_probe_dc_changed: ' + ('yes' if state.dc_changed else 'no'), file=sys.stderr)
        if exc.retry_after_seconds is not None:
            print(f'Wait at least {exc.retry_after_seconds} seconds; no automatic retry.', file=sys.stderr)
        return 1
    except Exception:
        print('telegram_standard_login: setup_failed (internal_error)', file=sys.stderr)
        return 1
    finally:
        if state.accepted and not (args.config_dir / 'telegram.json').exists():
            print('Accepted session retained privately; live reader disabled. '
                  'Do not rerun or move files; contact the operator.', file=sys.stderr)
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    raise SystemExit(main())
