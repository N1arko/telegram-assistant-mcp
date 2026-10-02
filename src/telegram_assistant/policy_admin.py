"""Local owner-only editor for the external send policy; never an MCP tool."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import secrets
import stat
import tempfile

from .security import Denied, Policy, integer, peer_id, private_file


def _check_directory(path: Path):
    if path.is_symlink():
        raise Denied("unsafe_policy_directory")
    st = path.stat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        raise Denied("unsafe_policy_directory")


def _check_external_policy(path: Path):
    _check_directory(path.parent)
    if any((ancestor / ".git").exists() for ancestor in (path.parent, *path.parent.parents)):
        raise Denied("policy_must_be_outside_repository")


def _open_lock(path: Path):
    lock = path.with_name(path.name + ".lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        os.close(fd)
        raise Denied("unsafe_policy_lock")
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def _atomic_write(path: Path, data):
    encoded = json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    fd, name = tempfile.mkstemp(prefix=".policy-", dir=path.parent)
    temp = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


def update_policy(path: Path, action: str, *, selector=None, peer_ids=(), expires_at=None,
                  max_chars=4096, per_minute=1, per_day=20, rule_id=None):
    path = Path(path)
    _check_external_policy(path)
    lock_fd = _open_lock(path)
    try:
        if path.is_symlink():
            raise Denied("unsafe_policy")
        if path.exists():
            raw_policy = json.loads(private_file(path))
            policy = Policy._parse(raw_policy)
            data = policy.to_data()
            if raw_policy.get("version") == 1:
                # Preserve v1 runtime behavior until an operator edits policy.
                # The explicit v2 migration adopts conservative bulk defaults.
                data["global_limits"] = {"per_minute": 5, "per_day": 100}
        else:
            data = Policy().to_data()
        ids = tuple(peer_id(value) for value in peer_ids)
        if len(ids) != len(set(ids)):
            raise Denied("duplicate_peer")
        expiry = None if expires_at is None else integer(expires_at, 1, 2**53)
        max_chars = integer(max_chars, 1, 4096)
        if action == "set_limits":
            per_minute = integer(per_minute, 1, 100)
            per_day = integer(per_day, 1, 1000)
        else:
            per_minute = integer(per_minute, 1, 10)
            per_day = integer(per_day, 1, 100)

        if action == "grant_peer":
            if len(ids) != 1 or any(g["peer_id"] == ids[0] for g in data["grants"]):
                raise Denied("invalid_or_duplicate_peer_grant")
            data["grants"].append({"peer_id": ids[0], "operation": "send_message", "expires_at": expiry,
                                   "max_chars": max_chars, "per_minute": per_minute, "per_day": per_day})
        elif action == "grant_rule":
            if selector not in {"all_human_dms", "group_ids", "all_groups", "first_contact"}:
                raise Denied("invalid_selector")
            if (selector == "group_ids") != bool(ids):
                raise Denied("invalid_selector_peers")
            if selector == "group_ids" and any(value >= 0 for value in ids):
                raise Denied("invalid_group_id")
            rule_id = rule_id or secrets.token_urlsafe(12)
            data["rules"].append({"id": rule_id, "operation": "send_message", "selector": selector,
                                  "peer_ids": list(ids), "expires_at": expiry,
                                  "max_chars": max_chars, "per_minute": per_minute, "per_day": per_day})
        elif action == "deny_peer":
            if len(ids) != 1 or any(d["peer_id"] == ids[0] for d in data["denies"]):
                raise Denied("invalid_or_duplicate_deny")
            data["denies"].append({"peer_id": ids[0], "expires_at": expiry})
        elif action == "allow_peer":
            if len(ids) != 1:
                raise Denied("invalid_peer")
            data["denies"] = [d for d in data["denies"] if d["peer_id"] != ids[0]]
        elif action == "revoke_peer":
            if len(ids) != 1:
                raise Denied("invalid_peer")
            data["grants"] = [g for g in data["grants"] if g["peer_id"] != ids[0]]
            retained = []
            for rule in data["rules"]:
                if rule["selector"] == "group_ids" and ids[0] in rule["peer_ids"]:
                    rule["peer_ids"].remove(ids[0])
                    if not rule["peer_ids"]:
                        continue
                retained.append(rule)
            data["rules"] = retained
        elif action == "revoke_rule":
            if not isinstance(rule_id, str) or not rule_id:
                raise Denied("invalid_rule_id")
            old_count = len(data["rules"])
            data["rules"] = [r for r in data["rules"] if r["id"] != rule_id]
            if len(data["rules"]) == old_count:
                raise Denied("rule_missing")
        elif action == "set_limits":
            data["global_limits"] = {"per_minute": per_minute, "per_day": per_day}
        else:
            raise Denied("invalid_policy_action")

        checked = Policy._parse(data)
        _atomic_write(path, checked.to_data())
        return rule_id if action == "grant_rule" else None
    finally:
        os.close(lock_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Edit the local owner-only Telegram send policy")
    parser.add_argument("--policy", required=True, type=Path, help="External private policy file")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("grant-peer", "deny-peer", "allow-peer", "revoke-peer"):
        command = sub.add_parser(action)
        command.add_argument("--peer-id", required=True, type=int)
        if action in {"grant-peer", "deny-peer"}:
            command.add_argument("--expires-at", type=int)
        if action == "grant-peer":
            command.add_argument("--max-chars", type=int, default=4096)
            command.add_argument("--per-minute", type=int, default=1)
            command.add_argument("--per-day", type=int, default=20)
    rules = sub.add_parser("grant-rule")
    rules.add_argument("--selector", required=True,
                       choices=("all_human_dms", "group_ids", "all_groups", "first_contact"))
    rules.add_argument("--peer-id", action="append", type=int, default=[])
    rules.add_argument("--expires-at", type=int)
    rules.add_argument("--max-chars", type=int, default=4096)
    rules.add_argument("--per-minute", type=int, default=1)
    rules.add_argument("--per-day", type=int, default=20)
    revoke = sub.add_parser("revoke-rule")
    revoke.add_argument("--rule-id", required=True)
    limits = sub.add_parser("set-global-quotas")
    limits.add_argument("--per-minute", required=True, type=int)
    limits.add_argument("--per-day", required=True, type=int)
    sub.add_parser("validate")

    args = parser.parse_args(argv)
    try:
        if args.action == "validate":
            _check_external_policy(args.policy)
            Policy.load_strict(args.policy)
            print("policy_valid")
            return 0
        action_map = {"grant-peer": "grant_peer", "deny-peer": "deny_peer", "allow-peer": "allow_peer",
                      "revoke-peer": "revoke_peer", "grant-rule": "grant_rule", "revoke-rule": "revoke_rule",
                      "set-global-quotas": "set_limits"}
        selected_peer_ids = getattr(args, "peer_id", ())
        if type(selected_peer_ids) is int:
            selected_peer_ids = (selected_peer_ids,)
        rule_id = update_policy(args.policy, action_map[args.action],
                                selector=getattr(args, "selector", None),
                                peer_ids=selected_peer_ids,
                                expires_at=getattr(args, "expires_at", None),
                                max_chars=getattr(args, "max_chars", 4096),
                                per_minute=getattr(args, "per_minute", 1),
                                per_day=getattr(args, "per_day", 20),
                                rule_id=getattr(args, "rule_id", None))
        print("policy_updated" + (f" rule_id={rule_id}" if rule_id else ""))
        return 0
    except (Denied, OSError, ValueError, TypeError):
        print("policy_update_failed", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
