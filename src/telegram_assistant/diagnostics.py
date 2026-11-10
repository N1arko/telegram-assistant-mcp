"""Bounded temporary diagnostic metadata; never persist request data."""
import contextvars
import json
import os
import re
import stat
import time

state = contextvars.ContextVar("telegram_diagnostic_state", default=None)
expires = time.time() + 86400

def stage(name):
    current = state.get()
    if current is not None:
        current["stage"] = name

def record(operation, backend, outcome, exc=None):
    try:
        if time.time() > expires:
            return
        current = state.get() or {}
        connected = backend.client.is_connected()
        name = type(exc).__name__ if exc is not None else None
        if name is not None and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,79}", name):
            name = "UnknownException"
        row = {"time_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "operation": operation, "stage": current.get("stage", "operation"),
               "outcome": outcome, "exception_class": name, "connected": bool(connected)}
        data = (json.dumps(row, separators=(",", ":")) + "\n").encode("ascii")
        fd = os.open("/state/telegram-mcp-diagnostics.jsonl", os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and st.st_size + len(data) <= 131072:
                os.write(fd, data)
        finally:
            os.close(fd)
    except Exception:
        pass
