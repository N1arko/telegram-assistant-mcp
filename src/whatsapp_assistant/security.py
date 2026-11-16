"""Private operator files, independent of Telegram state and policy."""
import os
import stat
import re
from pathlib import Path


class Denied(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def account_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", value):
        raise Denied("invalid_account_id")
    return value


def local_port(value):
    if type(value) is not int or not 1024 <= value <= 65535:
        raise Denied("invalid_port")
    return value


def private_file(path, max_bytes=65536):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                or st.st_mode & 0o077 or st.st_nlink != 1):
            raise Denied("unsafe_config")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise Denied("unsafe_config")
        return data
    finally:
        os.close(fd)
