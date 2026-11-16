"""Owner-only account catalogue and per-account MCP launcher. No account discovery tool."""
from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import re
import stat
import sys

from .auth import AuthConfig
from .security import Denied, account_id, local_port, private_file


@dataclass(frozen=True)
class Account:
    account_id: str
    private_dir: Path
    resource: str
    mcp_port: int
    bridge_port: int
    enable_write: bool = False

    @property
    def auth_file(self):
        return self.private_dir / "auth.json"

    @property
    def bridge_file(self):
        return self.private_dir / "bridge.json"

    @property
    def token_file(self):
        return self.private_dir / "state/bridge.token"


def private_directory(path):
    if not path.is_absolute() or str(path) != os.path.normpath(str(path)):
        raise Denied("unsafe_account_directory")
    for part in (path, *path.parents):
        if part.is_symlink() or (part / ".git").exists():
            raise Denied("unsafe_account_directory")
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise Denied("unsafe_account_directory")


def read_catalogue(path):
    """Validate identity, routing and storage collisions before reading credentials."""
    obj = json.loads(private_file(path))
    if (not isinstance(obj, dict) or set(obj) != {"version", "accounts"}
            or type(obj["version"]) is not int or obj["version"] != 1
            or not isinstance(obj["accounts"], list) or not 1 <= len(obj["accounts"]) <= 10):
        raise Denied("invalid_accounts_config")
    out = []
    for row in obj["accounts"]:
        required = {"account_id", "private_dir", "resource", "mcp_port", "bridge_port"}
        if not isinstance(row, dict) or not required <= row.keys() or row.keys() - required - {"enable_write"}:
            raise Denied("invalid_accounts_config")
        name = account_id(row["account_id"])
        directory, resource = row["private_dir"], row["resource"]
        if (not isinstance(directory, str) or not directory.startswith("/")
                or any(ord(c) < 32 for c in directory) or directory != os.path.normpath(directory)
                or not isinstance(resource, str)
                or not re.fullmatch(r"https://[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/mcp", resource)
                or type(row.get("enable_write", False)) is not bool):
            raise Denied("invalid_accounts_config")
        out.append(Account(name, Path(directory), resource, local_port(row["mcp_port"]),
                           local_port(row["bridge_port"]), row.get("enable_write", False)))
    if len({a.account_id for a in out}) != len(out) or len({a.resource for a in out}) != len(out):
        raise Denied("account_identity_conflict")
    ports = [p for a in out for p in (a.mcp_port, a.bridge_port)]
    if len(set(ports)) != len(ports):
        raise Denied("account_port_conflict")
    for i, left in enumerate(out):
        for right in out[i + 1:]:
            if (left.private_dir == right.private_dir or left.private_dir in right.private_dir.parents
                    or right.private_dir in left.private_dir.parents):
                raise Denied("account_storage_conflict")
    return tuple(out)


def validate_account_files(account, *, container=False):
    private_directory(account.private_dir)
    state = account.private_dir / "state"
    private_directory(state)
    auth = AuthConfig.load(account.auth_file)
    if auth.resource != account.resource:
        raise Denied("account_audience_mismatch")
    bridge = json.loads(private_file(account.bridge_file))
    root = "/state" if container else str(state)
    expected = {"account_id": account.account_id, "listen_port": account.bridge_port,
        "state_dir": root, "token_file": root + "/bridge.token", "key_file": root + "/history.key"}
    fields = set(expected) | {"expected_account_jid", "read_chats", "write_chats", "write_enabled", "per_minute",
                              "per_day", "encrypted_volume_confirmed"}
    optional_fields = {"read_access", "write_access"}
    if (not isinstance(bridge, dict) or not fields <= set(bridge) or set(bridge) - fields - optional_fields
            or any(bridge.get(k) != v for k, v in expected.items())
            or bridge.get("encrypted_volume_confirmed") is not True
            or type(bridge.get("write_enabled")) is not bool
            or bridge["write_enabled"] != account.enable_write
            or type(bridge.get("listen_port")) is not int):
        raise Denied("account_bridge_mismatch")
    if (not isinstance(bridge["expected_account_jid"], str)
            or not re.fullmatch(r"[0-9]{5,20}@s\.whatsapp\.net", bridge["expected_account_jid"])):
        raise Denied("expected_account_required")
    jid = re.compile(r"[0-9][0-9-]{0,79}@(s\.whatsapp\.net|g\.us|lid)")
    read_access = bridge.get("read_access", "allowlist")
    write_access = bridge.get("write_access", "allowlist")
    if (read_access not in {"allowlist", "all_chats"} or write_access not in {"allowlist", "all_chats"}
            or write_access == "all_chats" and read_access != "all_chats"):
        raise Denied("invalid_account_policy")
    for key in ("read_chats", "write_chats"):
        values = bridge[key]
        if (not isinstance(values, list) or len(values) > 1000
                or any(not isinstance(v, str) or not jid.fullmatch(v) for v in values)
                or len(set(values)) != len(values)):
            raise Denied("invalid_account_policy")
    if read_access == "allowlist" and not set(bridge["write_chats"]) <= set(bridge["read_chats"]):
        raise Denied("invalid_account_policy")
    for key, maximum in (("per_minute", 20), ("per_day", 500)):
        if type(bridge[key]) is not int or not 1 <= bridge[key] <= maximum:
            raise Denied("invalid_account_policy")
    if private_file(state / "account.id", 32).decode("ascii") != account.account_id:
        raise Denied("account_state_mismatch")
    secrets = []
    for name in ("bridge.token", "history.key"):
        value = private_file(state / name, 64)
        if len(value) != 64 or any(c not in b"0123456789abcdef" for c in value):
            raise Denied("invalid_account_secret")
        secrets.append(value)
    return secrets, bridge["expected_account_jid"]


def load_accounts(path, *, container=False):
    accounts = read_catalogue(path)
    secrets = []
    identities = []
    for account in accounts:
        keys, identity = validate_account_files(account, container=container)
        secrets.extend(keys)
        identities.append(identity)
    if len(set(secrets)) != len(secrets):
        raise Denied("account_secret_reused")
    if len(set(identities)) != len(identities):
        raise Denied("account_identity_reused")
    return accounts


def launch(account, *, container=False):
    from types import SimpleNamespace
    from .server import serve, require_runtime
    require_runtime()
    asyncio.run(serve(SimpleNamespace(auth_config=account.auth_file,
        bridge_token_file=account.token_file, account_id=account.account_id,
        port=account.mcp_port, bridge_port=account.bridge_port,
        enable_write=account.enable_write, container_network=container)))


def main():
    logging.disable(sys.maxsize)
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Validate isolated WhatsApp accounts or run one account's MCP")
    parser.add_argument("action", choices=("check", "mcp"))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--account")
    parser.add_argument("--container", action="store_true", help="Check Docker /state paths; deploy accounts in separate Compose projects")
    args = parser.parse_args()
    try:
        accounts = load_accounts(args.config, container=args.container)
        if args.action == "check":
            print(json.dumps({"valid": True, "accounts": [a.account_id for a in accounts]}))
            return
        if args.container:
            raise Denied("container_requires_separate_compose")
        chosen = next((a for a in accounts if a.account_id == args.account), None)
        if chosen is None:
            raise Denied("account_selection_required")
        launch(chosen, container=args.container)
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        code = exc.code if isinstance(exc, Denied) else "accounts_config_rejected"
        print(json.dumps({"error": code}), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
