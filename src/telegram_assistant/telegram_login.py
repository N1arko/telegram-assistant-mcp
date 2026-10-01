"""One-time, interactive provisioning for this project's dedicated Telegram session.

Run only from an SSH TTY with the separate login Compose file. The CLI reads all
prompts from one controlling terminal and never accepts secrets as arguments or
environment. API ID/hash/phone persist privately before login; OTP/password do not.
"""
from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import re
import stat
import sys
import tempfile
import termios
from pathlib import Path


class LoginSetupError(Exception):
    def __init__(self, code, *, retry_after_seconds=None):
        self.code = code
        self.retry_after_seconds = retry_after_seconds
        super().__init__(code)


def _confirmation_word(value: str) -> str:
    """Normalize only terminal framing around an explicit ASCII word."""
    if not isinstance(value, str):
        return ""
    value = value.strip()
    paste_start, paste_end = "\x1b[200~", "\x1b[201~"
    has_start, has_end = value.startswith(paste_start), value.endswith(paste_end)
    if has_start or has_end:
        if not (has_start and has_end):
            return ""
        value = value[len(paste_start):-len(paste_end)].strip()
    return value.upper() if value.isascii() else ""


def _confirmed_send(value: str) -> bool:
    return _confirmation_word(value) == "SEND"


def _secret_terminal_framing(value: str) -> str:
    """Remove only balanced terminal paste framing; preserve the secret itself.

    No strip/case/Unicode normalization. Partial/nested/control framing is
    rejected before the value can reach a network call.
    """
    if "\x1b" not in value:
        return value
    start, end = "\x1b[200~", "\x1b[201~"
    if value.startswith(start) and value.endswith(end):
        payload = value[len(start):-len(end)]
        if "\x1b" not in payload:
            return payload
    raise LoginSetupError("terminal_paste_framing_error")


def _confirmation_diagnostic(value: str) -> str:
    # Never emit raw input, code points, hashes or lengths: a misrouted input
    # could contain an account field. Categories alone diagnose terminal input.
    if not isinstance(value, str):
        return "invalid_input"
    if not value.strip():
        return "empty_line"
    if any(0xDC80 <= ord(char) <= 0xDCFF for char in value):
        return "invalid_utf8"
    if not value.isascii():
        return "non_ascii"
    if any(ord(char) < 32 and char not in "\t\r\n" for char in value):
        return "terminal_control"
    return "different_word"


def _request_confirmation(prompt, reader, word):
    while True:
        value = reader(prompt)
        normalized = _confirmation_word(value)
        if normalized == word:
            return
        if normalized == "CANCEL":
            raise LoginSetupError("cancelled")
        category = _confirmation_diagnostic(value)
        print(f"Confirmation rejected ({category}); no Telegram request was sent. "
              f"Type {word}, or CANCEL to exit.", file=sys.stderr, flush=True)


class _TTYConsole:
    """Use one controlling terminal and unbuffered reads for every prompt.

    No fallback to stdin/pipe or an echoing password reader is permitted.
    Terminal flags are restored on every return, failure and interruption.
    """
    def __enter__(self):
        try:
            self.fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY | os.O_CLOEXEC)
            if not os.isatty(self.fd):
                os.close(self.fd)
                raise OSError
        except OSError:
            raise LoginSetupError("controlling_tty_required") from None
        return self

    def __exit__(self, *_args):
        os.close(self.fd)

    def read(self, prompt, *, hidden=False):
        old = termios.tcgetattr(self.fd)
        new = old.copy()
        # Canonical erase must remove a complete UTF-8 character. Without
        # IUTF8, deleting Cyrillic leaves a leading byte and breaks decoding.
        # Python 3.12 on Linux omits IUTF8; the Linux UAPI bit is 0x4000.
        iutf8 = getattr(termios, "IUTF8", 0x4000 if sys.platform == "linux" else None)
        if iutf8 is None:
            raise LoginSetupError("utf8_terminal_flag_unavailable")
        new[0] = (new[0] | termios.ICRNL | iutf8) & ~(
            termios.INLCR | termios.IGNCR | termios.ISTRIP
        )
        new[3] |= termios.ICANON
        if hidden:
            new[3] &= ~(termios.ECHO | termios.ECHONL)
        else:
            new[3] |= termios.ECHO
        try:
            # Discard typeahead before showing a prompt. Consent must follow it.
            termios.tcsetattr(self.fd, termios.TCSAFLUSH, new)
            os.write(self.fd, prompt.encode("utf-8"))
            data = bytearray()
            while True:
                char = os.read(self.fd, 1)
                if not char:
                    raise LoginSetupError("terminal_input_closed")
                if char == b"\n":
                    break
                data.extend(char)
                if len(data) > 4096:
                    raise LoginSetupError("terminal_input_too_long")
            try:
                # Preserve malformed bytes in confirmation as non-ASCII
                # surrogates: reject the entire line and retry, never discard
                # bytes to turn a corrupted line into an accepted SEND.
                return data.decode("utf-8", errors="strict" if hidden else "surrogateescape")
            except UnicodeDecodeError:
                raise LoginSetupError("terminal_encoding_error") from None
        finally:
            termios.tcsetattr(self.fd, termios.TCSAFLUSH, old)
            if hidden:
                os.write(self.fd, b"\n")

    def secret(self, prompt):
        while True:
            try:
                return _secret_terminal_framing(self.read(prompt, hidden=True))
            except LoginSetupError as exc:
                if exc.code == "terminal_encoding_error":
                    message = "Invalid UTF-8 input; re-enter this field."
                elif exc.code == "terminal_paste_framing_error":
                    message = "Incomplete or unsupported terminal paste; re-enter this field."
                else:
                    raise
                print(message, file=sys.stderr, flush=True)

    def confirmation(self, prompt):
        return self.read(prompt)


def _secure_directory(path: Path) -> Path:
    try:
        if not path.is_absolute() or path.is_symlink():
            raise LoginSetupError("unsafe_directory")
        resolved = path.resolve(strict=True)
        st = path.stat(follow_symlinks=False)
        if (resolved != path or not stat.S_ISDIR(st.st_mode) or
                st.st_uid != os.geteuid() or st.st_mode & 0o077):
            raise LoginSetupError("unsafe_directory")
    except LoginSetupError:
        raise
    except Exception:
        raise LoginSetupError("unsafe_directory") from None
    return path


def _save_private_config(path: Path, payload: bytes, *, replace=False) -> None:
    """Atomically save mode-0600 config; replace only for explicit admin update."""
    fd, temp_name = tempfile.mkstemp(prefix=".telegram-config-", dir=path.parent)
    temp = Path(temp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        if replace:
            os.replace(temp, path)
        else:
            os.link(temp, path, follow_symlinks=False)
            temp.unlink()
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            temp.unlink()
        except OSError:
            pass
        raise LoginSetupError("private_config_write_failed") from None


def _validate_login_fields(api_id, api_hash, phone):
    if isinstance(api_id, str) and api_id.isascii() and api_id.isdecimal():
        api_id = int(api_id)
    if type(api_id) is not int or not 1 <= api_id <= 2**31 - 1:
        raise LoginSetupError("invalid_api_id")
    if not isinstance(api_hash, str) or not re.fullmatch(r"[A-Fa-f0-9]{32}", api_hash):
        raise LoginSetupError("invalid_api_hash")
    if not isinstance(phone, str) or not re.fullmatch(r"\+[1-9][0-9]{6,14}", phone):
        raise LoginSetupError("invalid_phone")
    return api_id, api_hash, phone


def _load_login_settings(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stored:
            st = os.fstat(stored.fileno())
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or
                    st.st_mode & 0o777 != 0o600 or st.st_nlink != 1):
                raise LoginSetupError("unsafe_login_config")
            raw = stored.read(4097)
            if len(raw) > 4096:
                raise LoginSetupError("login_config_invalid")
        def unique_pairs(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        data = json.loads(raw, object_pairs_hook=unique_pairs)
        if (not isinstance(data, dict) or set(data) != {"version", "api_id", "api_hash", "phone"} or
                type(data["version"]) is not int or data["version"] != 1):
            raise LoginSetupError("login_config_invalid")
        try:
            return _validate_login_fields(data["api_id"], data["api_hash"], data["phone"])
        except LoginSetupError:
            raise LoginSetupError("login_config_invalid") from None
    except LoginSetupError:
        raise
    except Exception:
        raise LoginSetupError("unsafe_login_config" if path.is_symlink() else "login_config_invalid") from None


def _login_settings(config_dir, secret_prompt, *, replace=False):
    path = config_dir / "login.json"
    exists = path.exists() or path.is_symlink()
    if exists:
        saved = _load_login_settings(path)
        if not replace:
            print("Saved API ID/hash/phone loaded from private login.json; values are hidden.",
                  file=sys.stderr, flush=True)
            return saved
    print("API ID/hash/phone will be saved privately in login.json (0600) before any login request. "
          "OTP and two-step password are never saved.", file=sys.stderr, flush=True)
    fields = _validate_login_fields(
        secret_prompt("Telegram API ID (hidden): ").strip(),
        secret_prompt("Telegram API hash (hidden): ").strip(),
        secret_prompt("Telegram phone in E.164 format (hidden): ").strip(),
    )
    payload = json.dumps(dict(version=1, api_id=fields[0], api_hash=fields[1], phone=fields[2]),
                         separators=(",", ":")).encode() + b"\n"
    try:
        _save_private_config(path, payload, replace=replace and exists)
    except LoginSetupError:
        raise LoginSetupError("private_login_config_write_failed") from None
    print(f"Login settings saved: {path}. They remain available after a failed login.",
          file=sys.stderr, flush=True)
    return fields


def _safe_login_failure(exc, phase):
    from telethon import errors
    mapping = (
        (errors.PhoneCodeInvalidError, "telegram_code_invalid"),
        (errors.PhoneCodeExpiredError, "telegram_code_expired"),
        (errors.PhoneCodeEmptyError, "telegram_code_empty"),
        (errors.PhoneCodeHashEmptyError, "telegram_code_hash_missing"),
        (errors.PasswordHashInvalidError, "telegram_password_invalid"),
        (errors.PasswordEmptyError, "telegram_password_empty"),
        (errors.PhoneNumberFloodError, "telegram_login_rate_limited"),
        (errors.PhoneNumberBannedError, "telegram_phone_banned"),
        (errors.PhoneNumberInvalidError, "telegram_phone_invalid"),
        (errors.PhoneNumberUnoccupiedError, "telegram_existing_account_required"),
        (errors.ApiIdInvalidError, "telegram_api_credentials_rejected"),
        (errors.AuthRestartError, "telegram_auth_restart_required"),
        (errors.SessionPasswordNeededError, "telegram_password_required"),
    )
    for kind, code in mapping:
        if isinstance(exc, kind):
            return LoginSetupError(code)
    if isinstance(exc, errors.FloodError):
        seconds = getattr(exc, "seconds", None)
        if type(seconds) is not int or not 0 <= seconds <= 2**31 - 1:
            seconds = None
        return LoginSetupError("telegram_flood_wait", retry_after_seconds=seconds)
    if isinstance(exc, asyncio.TimeoutError):
        return LoginSetupError("telegram_timeout_" + phase)
    if phase in {"code_prompt", "password_prompt"}:
        return LoginSetupError("terminal_input_failed")
    if isinstance(exc, errors.UnauthorizedError):
        return LoginSetupError("telegram_authorization_rejected_" + phase)
    if isinstance(exc, errors.RPCError):
        return LoginSetupError("telegram_rpc_rejected_" + phase)
    if isinstance(exc, OSError):
        return LoginSetupError("telegram_connection_failed_" + phase)
    return LoginSetupError("telegram_failed_" + phase)


def _remove_incomplete_session(path: Path) -> None:
    # The fixed target was checked absent before this invocation, so these can
    # only be transient SQLite files created by this failed setup attempt.
    for candidate in (path, Path(str(path) + "-journal"),
                      Path(str(path) + "-wal"), Path(str(path) + "-shm")):
        try:
            if not candidate.is_symlink():
                candidate.unlink(missing_ok=True)
        except OSError:
            pass


async def provision_session(*, config_dir: Path, session_dir: Path,
                            secret_prompt=None, confirm_prompt=None,
                            client_factory=None, timeout=30,
                            configure_only=False, replace_login_config=False):
    """Create the one configured personal-user session without exposing secrets."""
    if secret_prompt is None:
        secret_prompt = getpass.getpass
    if confirm_prompt is None:
        confirm_prompt = input
    config_dir = _secure_directory(Path(config_dir))
    session_dir = _secure_directory(Path(session_dir))
    config_path = config_dir / "telegram.json"
    session_path = session_dir / "assistant.session"
    if any(p.exists() or p.is_symlink() for p in (config_path, session_path)):
        raise LoginSetupError("target_already_exists")

    try:
        api_id, api_hash, phone = _login_settings(config_dir, secret_prompt, replace=replace_login_config)
        if configure_only:
            return config_dir / "login.json", None
        _request_confirmation(
            f"Request a Telegram login code for the number ending {phone[-4:]}? "
            "Type SEND (or CANCEL): ", confirm_prompt, "SEND",
        )
    except LoginSetupError:
        raise
    except Exception:
        raise LoginSetupError("prompt_failed") from None

    session_base = str(session_path.with_suffix(""))
    client = None
    authenticated = False
    saved_config = False
    phase = "client_setup"
    try:
        from telethon.errors import SessionPasswordNeededError
        if client_factory is None:
            from telethon import TelegramClient
            client_factory = TelegramClient
        client = client_factory(
            session_base, api_id, api_hash, receive_updates=False,
            flood_sleep_threshold=0, request_retries=0, connection_retries=1,
            raise_last_call_error=True,
        )
        phase = "connect"
        await asyncio.wait_for(client.connect(), timeout)
        phase = "authorization_check"
        if await asyncio.wait_for(client.is_user_authorized(), timeout):
            raise LoginSetupError("target_already_authorized")
        phase = "send_code"
        sent = await asyncio.wait_for(client.send_code_request(phone), timeout)
        phase = "code_prompt"
        code = secret_prompt("Telegram login code (hidden): ").strip()
        if not re.fullmatch(r"[0-9]{4,8}", code):
            raise LoginSetupError("invalid_login_code")
        try:
            phase = "sign_in_code"
            await asyncio.wait_for(client.sign_in(
                phone=phone, code=code, phone_code_hash=sent.phone_code_hash,
            ), timeout)
        except SessionPasswordNeededError:
            print("Telegram replied SESSION_PASSWORD_NEEDED for this login. If unexpected, "
                  "press Enter to stop and check the same account in the official app.",
                  file=sys.stderr, flush=True)
            phase = "password_prompt"
            password = secret_prompt("Telegram two-step verification password (hidden; Enter to stop): ")
            if not password:
                raise LoginSetupError("telegram_password_required")
            phase = "sign_in_password"
            await asyncio.wait_for(client.sign_in(password=password), timeout)
        phase = "verify_authorization"
        authenticated = await asyncio.wait_for(client.is_user_authorized(), timeout)
        if not authenticated:
            raise LoginSetupError("telegram_authorization_failed")

        try:
            if not session_path.is_file() or session_path.is_symlink():
                raise OSError
            os.chmod(session_path, 0o600, follow_symlinks=False)
            document = {
                "api_id": api_id,
                "api_hash": api_hash,
                "session_file": str(session_path),
            }
            encoded = (json.dumps(document, separators=(",", ":")) + "\n").encode()
            _save_private_config(config_path, encoded)
            saved_config = True
        except LoginSetupError:
            raise
        except Exception:
            raise LoginSetupError("private_config_write_failed") from None
    except LoginSetupError:
        raise
    except Exception as exc:
        raise _safe_login_failure(exc, phase) from None
    finally:
        if client is not None:
            try:
                await asyncio.wait_for(client.disconnect(), min(timeout, 10))
            except BaseException:
                pass
        if not authenticated and not saved_config:
            _remove_incomplete_session(session_path)

    try:
        st = session_path.stat(follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise OSError
        config_st = config_path.stat(follow_symlinks=False)
        if not stat.S_ISREG(config_st.st_mode) or config_st.st_uid != os.geteuid() or config_st.st_mode & 0o077:
            raise OSError
    except Exception:
        raise LoginSetupError("private_file_verification_failed") from None
    return config_path, session_path


async def _run(args):
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise LoginSetupError("interactive_tty_required")
    os.umask(0o077)
    # Telethon's RPC diagnostics can include identifiers. The setup console
    # emits only fixed prompts and fixed result/error codes.
    logging.disable(logging.CRITICAL)
    logging.getLogger("telethon").disabled = True
    with _TTYConsole() as console:
        _request_confirmation(
            "Terminal check; no account data or network. Type CHECK (or CANCEL): ",
            console.confirmation, "CHECK",
        )
        print("Terminal check passed.", file=sys.stderr, flush=True)
        if not getattr(args, "check_terminal", False):
            await provision_session(
                config_dir=args.config_dir, session_dir=args.session_dir,
                secret_prompt=console.secret, confirm_prompt=console.confirmation,
                configure_only=getattr(args, "configure_login", False) or getattr(args, "replace_login_config", False),
                replace_login_config=getattr(args, "replace_login_config", False),
            )


def main():
    parser = argparse.ArgumentParser(description="Create a private Telegram user session for this MCP")
    parser.add_argument("--config-dir", type=Path, default=Path("/run/telegram"))
    parser.add_argument("--session-dir", type=Path, default=Path("/sessions"))
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check-terminal", action="store_true",
                        help="Check terminal input only; do not read account config or contact Telegram")
    modes.add_argument("--configure-login", action="store_true",
                       help="Save or reuse private API ID/hash/phone and exit without contacting Telegram")
    modes.add_argument("--replace-login-config", action="store_true",
                       help="Explicit admin path: enter replacement login settings and exit without contacting Telegram")
    args = parser.parse_args()
    try:
        asyncio.run(_run(args))
        if args.check_terminal:
            print("Terminal check complete. No account data was read and no Telegram request was sent.")
        elif args.configure_login or args.replace_login_config:
            print("Private login settings are ready. No Telegram request was sent.")
        else:
            print("Telegram session and private config saved. No MCP service was started.")
        return 0
    except KeyboardInterrupt:
        print("telegram_login: cancelled", file=sys.stderr)
        return 130
    except LoginSetupError as exc:
        print(f"telegram_login: setup_failed ({exc.code})", file=sys.stderr)
        if exc.retry_after_seconds is not None:
            print(f"Retry no sooner than {exc.retry_after_seconds} seconds; no automatic retry was made.", file=sys.stderr)
        if exc.code in {"telegram_password_required", "telegram_password_invalid"}:
            print("Check Settings > Privacy and Security > Two-Step Verification for the same phone "
                  "in the official Telegram app. Saved login settings are retained.", file=sys.stderr)
        if exc.code == "private_config_write_failed":
            print("A private authorized session may exist; do not rerun or copy files. Contact the operator.", file=sys.stderr)
        return 1
    except Exception:
        print("telegram_login: setup_failed (internal_error)", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
