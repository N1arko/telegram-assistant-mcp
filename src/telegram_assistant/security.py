"""Local limits and operator policy; never interpret semantic permission."""
from __future__ import annotations

import json
import math
import os
import sqlite3
import stat
import tempfile
import time
import fcntl
from collections import deque
from dataclasses import dataclass
from pathlib import Path


class Denied(Exception):
    def __init__(self, code: str, retry_after: int | None = None):
        self.code = code
        self.retry_after = retry_after
        super().__init__(code)


def integer(value, low: int, high: int, code="invalid_argument") -> int:
    if type(value) is not int or not low <= value <= high:
        raise Denied(code)
    return value


def peer_id(value) -> int:
    value = integer(value, -(2**63) + 1, 2**63 - 1)
    if value == 0:
        raise Denied("invalid_peer")
    return value


def private_file(path: Path, max_bytes=65536) -> bytes:
    """No symlinks, regular owner-only files. O_NOFOLLOW blocks final-link races."""
    if path.is_symlink():
        raise Denied("unsafe_config")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
            raise Denied("unsafe_config")
        data = os.read(fd, max_bytes + 1)
        if len(data) > max_bytes:
            raise Denied("unsafe_config")
        return data
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Grant:
    peer_id: int
    expires_at: int | None
    max_chars: int
    per_minute: int
    per_day: int
    selector: str = "peer"
    rule_id: str | None = None
    first_contact: bool = False
    global_per_minute: int = 5
    global_per_day: int = 100

    def active(self, now):
        return self.expires_at is None or now < self.expires_at


@dataclass(frozen=True)
class RecipientRule:
    rule_id: str
    selector: str
    peer_ids: tuple[int, ...]
    expires_at: int | None
    max_chars: int
    per_minute: int
    per_day: int

    def active(self, now):
        return self.expires_at is None or now < self.expires_at

    def coarse_match(self, target):
        if self.selector == "all_human_dms":
            return target > 0
        if self.selector in {"all_groups", "group_ids"}:
            return target < 0 if self.selector == "all_groups" else target in self.peer_ids
        if self.selector == "first_contact":
            return target > 0
        return False


@dataclass(frozen=True)
class DenyRule:
    peer_id: int
    expires_at: int | None = None

    def active(self, now):
        return self.expires_at is None or now < self.expires_at


class Policy:
    def __init__(self, grants=(), rules=(), denies=(), *, global_per_minute=5, global_per_day=100):
        self.grants = {g.peer_id: g for g in grants}
        self.rules = tuple(rules)
        self.denies = tuple(denies)
        self.global_per_minute = global_per_minute
        self.global_per_day = global_per_day

    @staticmethod
    def _expiry(value):
        return None if value is None else integer(value, 1, 2**53)

    @classmethod
    def _parse(cls, obj):
        if not isinstance(obj, dict) or type(obj.get("version")) is not int:
            raise Denied("invalid_policy")
        version = obj["version"]
        if version == 1:
            if set(obj) != {"version", "grants"}:
                raise Denied("invalid_policy")
            rules, denies, global_limits = [], [], None
        elif version == 2:
            if set(obj) != {"version", "grants", "rules", "denies", "global_limits"}:
                raise Denied("invalid_policy")
            rules, denies, global_limits = obj["rules"], obj["denies"], obj["global_limits"]
            if (not isinstance(rules, list) or len(rules) > 100 or
                    not isinstance(denies, list) or len(denies) > 1000 or
                    not isinstance(global_limits, dict) or
                    set(global_limits) != {"per_minute", "per_day"}):
                raise Denied("invalid_policy")
        else:
            raise Denied("invalid_policy")
        if not isinstance(obj["grants"], list) or len(obj["grants"]) > 100:
            raise Denied("invalid_policy")
        grants = []
        grant_fields = {"peer_id", "operation", "expires_at", "max_chars", "per_minute", "per_day"}
        for item in obj["grants"]:
            if not isinstance(item, dict) or set(item) != grant_fields or item["operation"] != "send_message":
                raise Denied("invalid_policy")
            grants.append(Grant(peer_id(item["peer_id"]), cls._expiry(item["expires_at"]),
                                integer(item["max_chars"], 1, 4096), integer(item["per_minute"], 1, 10),
                                integer(item["per_day"], 1, 100)))
        if len({g.peer_id for g in grants}) != len(grants):
            raise Denied("invalid_policy")
        parsed_rules = []
        rule_fields = {"id", "operation", "selector", "peer_ids", "expires_at", "max_chars", "per_minute", "per_day"}
        selectors = {"all_human_dms", "group_ids", "all_groups", "first_contact"}
        for item in rules:
            if not isinstance(item, dict) or set(item) != rule_fields or item["operation"] != "send_message":
                raise Denied("invalid_policy")
            selector, ids = item["selector"], item["peer_ids"]
            if selector not in selectors or not isinstance(item["id"], str) or not 1 <= len(item["id"]) <= 64:
                raise Denied("invalid_policy")
            if not isinstance(ids, list) or (selector == "group_ids") != bool(ids):
                raise Denied("invalid_policy")
            ids = tuple(peer_id(x) for x in ids)
            if (len(ids) > 1000 or len(ids) != len(set(ids)) or
                    (selector == "group_ids" and any(x >= 0 for x in ids))):
                raise Denied("invalid_policy")
            parsed_rules.append(RecipientRule(item["id"], selector, ids, cls._expiry(item["expires_at"]),
                                              integer(item["max_chars"], 1, 4096),
                                              integer(item["per_minute"], 1, 10),
                                              integer(item["per_day"], 1, 100)))
        if len({r.rule_id for r in parsed_rules}) != len(parsed_rules):
            raise Denied("invalid_policy")
        parsed_denies = []
        for item in denies:
            if not isinstance(item, dict) or set(item) != {"peer_id", "expires_at"}:
                raise Denied("invalid_policy")
            parsed_denies.append(DenyRule(peer_id(item["peer_id"]), cls._expiry(item["expires_at"])))
        if len({d.peer_id for d in parsed_denies}) != len(parsed_denies):
            raise Denied("invalid_policy")
        limits = ((1000, 10000) if version == 1 else
                  (integer(global_limits["per_minute"], 1, 1000),
                   integer(global_limits["per_day"], 1, 10000)))
        return cls(grants, parsed_rules, parsed_denies,
                   global_per_minute=limits[0], global_per_day=limits[1])

    @classmethod
    def load(cls, path: Path) -> Policy:
        # Any file/config failure means empty grants, never implicit permission.
        try:
            return cls._parse(json.loads(private_file(path)))
        except (OSError, ValueError, TypeError, KeyError, Denied):
            return cls()

    @classmethod
    def load_strict(cls, path: Path) -> Policy:
        return cls._parse(json.loads(private_file(path)))

    def to_data(self):
        return {"version": 2,
                "grants": [{"peer_id": g.peer_id, "operation": "send_message", "expires_at": g.expires_at,
                            "max_chars": g.max_chars, "per_minute": g.per_minute, "per_day": g.per_day}
                           for g in self.grants.values()],
                "rules": [{"id": r.rule_id, "operation": "send_message", "selector": r.selector,
                           "peer_ids": list(r.peer_ids), "expires_at": r.expires_at,
                           "max_chars": r.max_chars, "per_minute": r.per_minute, "per_day": r.per_day}
                          for r in self.rules],
                "denies": [{"peer_id": d.peer_id, "expires_at": d.expires_at} for d in self.denies],
                "global_limits": {"per_minute": self.global_per_minute, "per_day": self.global_per_day}}

    def candidates(self, target, now):
        target = peer_id(target)
        if any(d.peer_id == target and d.active(now) for d in self.denies):
            raise Denied("send_denied")
        matches = []
        exact = self.grants.get(target)
        if exact is not None and exact.active(now):
            matches.append(exact)
        for rule in self.rules:
            if rule.active(now) and rule.coarse_match(target):
                matches.append(Grant(target, rule.expires_at, rule.max_chars, rule.per_minute,
                                     rule.per_day, selector=rule.selector, rule_id=rule.rule_id,
                                     first_contact=rule.selector == "first_contact"))
        if not matches:
            raise Denied("send_denied")
        return tuple(matches)

    def precheck(self, target, text, scopes, now):
        if "telegram:send" not in scopes:
            raise Denied("send_scope_required")
        candidates = self.candidates(target, now)
        if not isinstance(text, str) or not text.strip():
            raise Denied("invalid_text")
        try:
            units = len(text.encode("utf-16-le")) // 2
        except UnicodeError:
            raise Denied("invalid_text") from None
        if units > min(g.max_chars for g in candidates):
            raise Denied("text_too_long")
        return candidates

    def authorize(self, target: int, text: str, scopes: frozenset[str], now: float, *,
                  peer_type=None, is_human=False, first_contact_verified=False) -> Grant:
        candidates = self.precheck(target, text, scopes, now)
        matched = []
        for grant in candidates:
            if grant.selector == "peer" and (
                    peer_type == "group" or (peer_type == "user" and is_human)):
                matched.append(grant)
            elif grant.selector == "all_human_dms" and peer_type == "user" and is_human:
                matched.append(grant)
            elif grant.selector in {"group_ids", "all_groups"} and peer_type == "group":
                matched.append(grant)
            elif grant.selector == "first_contact" and peer_type == "user" and is_human and first_contact_verified:
                matched.append(grant)
        if not matched:
            raise Denied("send_denied")
        # UTF-16 length was checked before contact resolution, then rechecked
        # here so changed/expired policy cannot outlive the async lookup.
        units = len(text.encode("utf-16-le")) // 2
        if units > min(g.max_chars for g in matched):
            raise Denied("text_too_long")
        expiry = None if any(g.expires_at is None for g in matched) else max(g.expires_at for g in matched)
        return Grant(target, expiry, min(g.max_chars for g in matched),
                     min(g.per_minute for g in matched), min(g.per_day for g in matched),
                     selector="combined", rule_id=",".join(sorted(g.rule_id for g in matched if g.rule_id)) or None,
                     first_contact=any(g.first_contact for g in matched),
                     global_per_minute=self.global_per_minute, global_per_day=self.global_per_day)


class Quotas:
    """Reserve before RPC, including failures; SQLite survives restarts."""
    def __init__(self, path: Path):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if path.parent.is_symlink() or path.parent.stat().st_mode & 0o077:
            raise Denied("unsafe_runtime")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
                raise Denied("unsafe_runtime")
        finally:
            os.close(fd)
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS attempts (peer INTEGER, at REAL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS attempts_lookup ON attempts(peer, at)")
        self.db.execute("CREATE INDEX IF NOT EXISTS attempts_time_lookup ON attempts(at)")
        self.db.execute("CREATE TABLE IF NOT EXISTS first_contact_attempts (peer INTEGER, message_id INTEGER, at REAL, state TEXT, PRIMARY KEY(peer,message_id))")
        self.db.execute("CREATE TABLE IF NOT EXISTS read_gate (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT)")
        self.db.commit()

    def load_gate(self):
        row = self.db.execute('SELECT state FROM read_gate WHERE id=1').fetchone()
        if row is None:
            return None
        if len(row[0]) > 4096:
            raise Denied('rate_state_unavailable')
        return json.loads(row[0])

    def save_gate(self, state):
        self.db.execute('INSERT OR REPLACE INTO read_gate VALUES(1, ?)',
                        (json.dumps(state, allow_nan=False, separators=(',', ':')),))
        self.db.commit()

    def reserve(self, grant: Grant, now: float, *, first_contact_message_id=None):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            # A rolling 24-hour limit; no reset-at-midnight burst.
            self.db.execute("DELETE FROM attempts WHERE at <= ?", (now - 86400,))
            if grant.first_contact:
                if first_contact_message_id is None:
                    raise Denied("first_contact_message_required")
                try:
                    self.db.execute("INSERT INTO first_contact_attempts VALUES (?,?,?,'reserved')",
                                    (grant.peer_id, first_contact_message_id, now))
                except sqlite3.IntegrityError:
                    raise Denied("first_contact_already_handled") from None
            rows = self.db.execute("SELECT at FROM attempts WHERE peer=? AND at>? ORDER BY at",
                                   (grant.peer_id, now - 86400)).fetchall()
            recent = [at for (at,) in rows if at > now - 60]
            if len(rows) >= grant.per_day or len(recent) >= grant.per_minute:
                raise Denied("send_quota_exceeded")
            all_rows = self.db.execute("SELECT at FROM attempts WHERE at>? ORDER BY at", (now - 86400,)).fetchall()
            all_recent = [at for (at,) in all_rows if at > now - 60]
            if len(all_rows) >= grant.global_per_day or len(all_recent) >= grant.global_per_minute:
                raise Denied("send_quota_exceeded")
            self.db.execute("INSERT INTO attempts VALUES (?, ?)", (grant.peer_id, now))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def finish_first_contact(self, peer, message_id, state):
        if state not in {"sent", "unknown"}:
            raise ValueError("invalid delivery state")
        self.db.execute("UPDATE first_contact_attempts SET state=? WHERE peer=? AND message_id=?",
                        (state, peer, message_id))
        self.db.commit()

    def close(self):
        self.db.close()


class RateGate:
    def __init__(self, limit=30, clock=time.monotonic, *, storage=None, wall_clock=time.time, startup_grace=0):
        self.clock = clock
        self.limit = limit
        self.calls = deque()
        self.blocked_until = 0.0
        self.storage, self.wall_clock = storage, wall_clock
        self.failed = False
        now, wall = self.clock(), self.wall_clock()
        if storage is not None:
            try:
                state = storage.load_gate()
                if state is not None:
                    valid_number = lambda value: type(value) in (int, float) and math.isfinite(value) and value >= 0
                    if (not isinstance(state, dict) or set(state) != {'version', 'flood_until', 'calls'} or
                            type(state['version']) is not int or state['version'] != 1 or
                            not valid_number(state['flood_until']) or not isinstance(state['calls'], list) or
                            len(state['calls']) > limit or not all(valid_number(x) for x in state['calls']) or
                            state['calls'] != sorted(state['calls'])):
                        raise ValueError
                    self.blocked_until = now + max(0, state['flood_until'] - wall)
                    # If wall time moves backwards, keep entries conservatively
                    # rather than dropping a persisted quota.
                    self.calls.extend(now - max(0, wall - x) for x in state['calls'] if x > wall - 60)
                self.blocked_until = max(self.blocked_until, now + startup_grace)
                self._persist()
            except Exception:
                raise Denied('rate_state_unavailable') from None

    def _persist(self):
        if self.storage is None:
            return
        now, wall = self.clock(), self.wall_clock()
        try:
            self.storage.save_gate({'version': 1, 'flood_until': wall + max(0, self.blocked_until - now),
                                    'calls': [wall - max(0, now - at) for at in self.calls]})
        except Exception:
            self.failed = True
            raise Denied('rate_state_unavailable') from None

    def check(self):
        if self.failed:
            raise Denied('rate_state_unavailable')
        now = self.clock()
        if now < self.blocked_until:
            raise Denied("telegram_rate_limited", math.ceil(self.blocked_until - now))
        while self.calls and self.calls[0] <= now - 60:
            self.calls.popleft()
        if len(self.calls) >= self.limit:
            raise Denied("local_rate_limited", math.ceil(60 - (now - self.calls[0])))
        self.calls.append(now)
        self._persist()

    def flood(self, seconds: int):
        self.blocked_until = max(self.blocked_until, self.clock() + max(1, seconds))
        try:
            self._persist()
        except Denied:
            # Subsequent checks fail closed; do not lose the original flood
            # response or accidentally retry a failed Telegram operation.
            self.failed = True
