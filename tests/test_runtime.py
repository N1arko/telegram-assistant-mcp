import contextlib
import io
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from telegram_assistant.server import silence_logs, main
from telegram_assistant.session_lock import SessionLock, SessionLockError


class RuntimeTests(unittest.TestCase):
    def test_session_lock_exclusive_and_release(self):
        with tempfile.TemporaryDirectory() as d:
            one=SessionLock("one","/new/session/path",lock_dir=Path(d))
            two=SessionLock("two","/new/session/path",lock_dir=Path(d))
            one.acquire(grace_seconds=0)
            with self.assertRaises(SessionLockError):two.acquire(grace_seconds=0)
            one.release()
            two.acquire(grace_seconds=0)
            two.release()
    def test_startup_failure_masks_secret(self):
        previous=logging.root.manager.disable
        try:
            with patch("sys.argv",["telegram-assistant-mcp","--auth-config","/not/used",
                    "--telegram-config","/not/used","--policy","/not/used","--runtime-dir","/not/used"]), \
                 patch("telegram_assistant.server.serve",AsyncMock(side_effect=RuntimeError("session-text-token-secret"))), \
                 contextlib.redirect_stderr(io.StringIO()) as stderr:
                with self.assertRaises(SystemExit):main()
                self.assertNotIn("session-text-token-secret",stderr.getvalue())
                self.assertIn("startup_or_runtime_failed",stderr.getvalue())
        finally:
            logging.disable(previous)
    def test_libraries_cannot_log_secrets_under_entrypoint_policy(self):
        previous=logging.root.manager.disable
        stream=io.StringIO()
        handler=logging.StreamHandler(stream)
        logging.getLogger().addHandler(handler)
        try:
            silence_logs()
            for name in ["telethon", "httpx", "mcp.server", "uvicorn.error"]:
                logging.getLogger(name).critical("SESSION_TOKEN_AND_MESSAGE_BODY")
            self.assertEqual(stream.getvalue(),"")
        finally:
            logging.getLogger().removeHandler(handler)
            logging.disable(previous)
