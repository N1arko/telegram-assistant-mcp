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
    per_minute: int | None
    per_day: int | None
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
    QUOTA_MODES = ("recipient_and_global", "global_only")

    def __init__(self, grants=(), rules=(), denies=(), *, global_per_minute=5, global_per_day=100,
                 quota_mode="recipient_and_global"):
        self.grants = {g.peer_id: g for g in grants}
        self.rules = tuple(rules)
        self.denies = tuple(denies)
        self.global_per_minute = global_per_minute
        self.global_per_day = global_per_day
        self.quota_mode = quota_mode

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
            quota_mode = "recipient_and_global"
        elif version == 2:
            required_fields = {"version", "grants", "rules", "denies", "global_limits"}
            if not required_fields <= set(obj) or set(obj) - required_fields - {"quota_mode"}:
                raise Denied("invalid_policy")
            rules, denies, global_limits = obj["rules"], obj["denies"], obj["global_limits"]
            quota_mode = obj.get("quota_mode", "recipient_and_global")
            if (not isinstance(rules, list) or len(rules) > 100 or
                    not isinstance(denies, list) or len(denies) > 1000 or
                    not isinstance(global_limits, dict) or
                    set(global_limits) != {"per_minute", "per_day"}):
                raise Denied("invalid_policy")
        else:
            raise Denied("invalid_policy")
        if quota_mode not in cls.QUOTA_MODES:
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
                   global_per_minute=limits[0], global_per_day=limits[1], quota_mode=quota_mode)

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
                "global_limits": {"per_minute": self.global_per_minute, "per_day": self.global_per_day},
                "quota_mode": self.quota_mode}

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

    def precheck_media(self, target, captions, scopes, now):
        if "telegram:send" not in scopes:
            raise Denied("send_scope_required")
        candidates = tuple(g for g in self.candidates(target, now) if not g.first_contact)
        if not candidates:
            raise Denied("send_denied")
        if not isinstance(captions, (list, tuple)):
            raise Denied("invalid_media_caption")
        for caption in captions:
            if caption is None:
                continue
            if not isinstance(caption, str):
                raise Denied("invalid_media_caption")
            try:
                units = len(caption.encode("utf-16-le")) // 2
            except UnicodeError:
                raise Denied("invalid_media_caption") from None
            if units > min(g.max_chars for g in candidates):
                raise Denied("text_too_long")
        return candidates

    def _recipient_limits(self, matched):
        if self.quota_mode == "global_only":
            return None, None
        return min(g.per_minute for g in matched), min(g.per_day for g in matched)

    def authorize_media(self, target: int, captions, scopes: frozenset[str], now: float, *,
                        peer_type=None, is_human=False) -> Grant:
        candidates = self.precheck_media(target, captions, scopes, now)
        matched = []
        for grant in candidates:
            if grant.selector == "peer" and (
                    peer_type == "group" or (peer_type == "user" and is_human)):
                matched.append(grant)
            elif grant.selector == "all_human_dms" and peer_type == "user" and is_human:
                matched.append(grant)
            elif grant.selector in {"group_ids", "all_groups"} and peer_type == "group":
                matched.append(grant)
        if not matched:
            raise Denied("send_denied")
        for caption in captions:
            if caption is not None and len(caption.encode("utf-16-le")) // 2 > min(g.max_chars for g in matched):
                raise Denied("text_too_long")
        expiry = None if any(g.expires_at is None for g in matched) else max(g.expires_at for g in matched)
        per_minute, per_day = self._recipient_limits(matched)
        return Grant(target, expiry, min(g.max_chars for g in matched),
                     per_minute, per_day,
                     selector="combined", rule_id=",".join(sorted(g.rule_id for g in matched if g.rule_id)) or None,
                     global_per_minute=self.global_per_minute, global_per_day=self.global_per_day)

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
        per_minute, per_day = self._recipient_limits(matched)
        return Grant(target, expiry, min(g.max_chars for g in matched),
                     per_minute, per_day,
                     selector="combined", rule_id=",".join(sorted(g.rule_id for g in matched if g.rule_id)) or None,
                     first_contact=any(g.first_contact for g in matched),
                     global_per_minute=self.global_per_minute, global_per_day=self.global_per_day)


class Quotas:
    """Reserve before RPC, including failures; SQLite survives restarts."""
    MONITOR_FIRST_DM_WINDOW_MESSAGES = 20

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
        self.db.execute("CREATE TABLE IF NOT EXISTS transcription_usage (month TEXT PRIMARY KEY, seconds INTEGER NOT NULL)")
        # The incremental reader persists only peer/message IDs and opaque
        # cursors. Message text and media are never stored in this database.
        self.db.execute("CREATE TABLE IF NOT EXISTS monitor_checkpoints (peer INTEGER PRIMARY KEY, message_id INTEGER NOT NULL, peer_type TEXT NOT NULL, initial_window_limited INTEGER NOT NULL DEFAULT 0)")
        checkpoint_columns = {row[1] for row in self.db.execute("PRAGMA table_info(monitor_checkpoints)")}
        if "initial_window_limited" not in checkpoint_columns:
            self.db.execute("ALTER TABLE monitor_checkpoints ADD COLUMN initial_window_limited INTEGER NOT NULL DEFAULT 0")
        self.db.execute("CREATE TABLE IF NOT EXISTS monitor_pending (sequence INTEGER PRIMARY KEY AUTOINCREMENT, peer INTEGER NOT NULL UNIQUE, after_id INTEGER NOT NULL, through_id INTEGER NOT NULL, peer_type TEXT NOT NULL, priority INTEGER NOT NULL DEFAULT 0)")
        pending_columns = {row[1] for row in self.db.execute("PRAGMA table_info(monitor_pending)")}
        if "priority" not in pending_columns:
            self.db.execute("ALTER TABLE monitor_pending ADD COLUMN priority INTEGER NOT NULL DEFAULT 0")
        self.db.execute("CREATE TABLE IF NOT EXISTS monitor_state (id INTEGER PRIMARY KEY CHECK(id=1), state TEXT NOT NULL)")
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

    def reserve(self, grant: Grant, now: float, *, first_contact_message_id=None, count=1):
        integer(count, 1, 10, "send_quota_exceeded")
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
            if (grant.per_minute is None) != (grant.per_day is None):
                raise Denied("send_quota_unavailable")
            if grant.per_minute is not None:
                rows = self.db.execute("SELECT at FROM attempts WHERE peer=? AND at>? ORDER BY at",
                                       (grant.peer_id, now - 86400)).fetchall()
                recent = [at for (at,) in rows if at > now - 60]
                if len(rows) + count > grant.per_day or len(recent) + count > grant.per_minute:
                    raise Denied("send_quota_exceeded")
            all_rows = self.db.execute("SELECT at FROM attempts WHERE at>? ORDER BY at", (now - 86400,)).fetchall()
            all_recent = [at for (at,) in all_rows if at > now - 60]
            if len(all_rows) + count > grant.global_per_day or len(all_recent) + count > grant.global_per_minute:
                raise Denied("send_quota_exceeded")
            self.db.executemany("INSERT INTO attempts VALUES (?, ?)",
                                ((grant.peer_id, now) for _ in range(count)))
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

    def reserve_transcription(self, seconds: int, monthly_limit: int, now: float):
        """Reserve billable audio seconds transactionally before a provider call."""
        if (type(seconds) is not int or seconds < 1 or type(monthly_limit) is not int or
                monthly_limit < 1 or type(now) not in (int, float) or not math.isfinite(now)):
            raise Denied("transcription_budget_unavailable")
        month = time.strftime("%Y-%m", time.gmtime(now))
        self.db.execute("BEGIN IMMEDIATE")
        try:
            row = self.db.execute("SELECT seconds FROM transcription_usage WHERE month=?", (month,)).fetchone()
            used = row[0] if row is not None else 0
            if type(used) is not int or used < 0:
                raise Denied("transcription_budget_unavailable")
            if used + seconds > monthly_limit:
                raise Denied("transcription_budget_exceeded")
            self.db.execute("INSERT OR REPLACE INTO transcription_usage VALUES(?, ?)",
                            (month, used + seconds))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    @staticmethod
    def _default_monitor_state():
        return {"version": 3, "catalog_cursor": None, "catalog_checkpoint": None,
                "catalog_calls_since_refresh": 0, "catalog_finished": False,
                "catalog_complete": False, "catalog_truncated": False,
                "catalog_sweeps_completed": False, "coverage_restarted": False, "sweep_started": False,
                "last_acked_cursor": None, "inflight": None}

    @classmethod
    def _validate_monitor_state(cls, state):
        # Upgrade the schema written by earlier releases without discarding
        # durable delivery/checkpoint state.
        old_fields = {"version", "catalog_cursor", "catalog_finished", "catalog_complete",
                      "catalog_truncated", "coverage_restarted", "sweep_started",
                      "last_acked_cursor", "inflight"}
        if isinstance(state, dict) and state.get("version") == 1 and set(state) == old_fields:
            state = {**state, "version": 2, "catalog_checkpoint": None,
                     "catalog_calls_since_refresh": 0}
        v2_fields = {"version", "catalog_cursor", "catalog_checkpoint", "catalog_calls_since_refresh",
                     "catalog_finished", "catalog_complete", "catalog_truncated",
                     "coverage_restarted", "sweep_started", "last_acked_cursor", "inflight"}
        if isinstance(state, dict) and state.get("version") == 2 and set(state) == v2_fields:
            state = {**state, "version": 3, "catalog_sweeps_completed": False}
        fields = {"version", "catalog_cursor", "catalog_checkpoint", "catalog_calls_since_refresh",
                  "catalog_finished", "catalog_complete", "catalog_sweeps_completed",
                  "catalog_truncated", "coverage_restarted", "sweep_started",
                  "last_acked_cursor", "inflight"}
        if (not isinstance(state, dict) or set(state) != fields or
                type(state.get("version")) is not int or state["version"] != 3):
            raise Denied("monitor_state_unavailable")
        for name in ("catalog_finished", "catalog_complete", "catalog_sweeps_completed", "catalog_truncated",
                     "coverage_restarted", "sweep_started"):
            if type(state[name]) is not bool:
                raise Denied("monitor_state_unavailable")
        for name in ("catalog_cursor", "last_acked_cursor"):
            value = state[name]
            if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 128):
                raise Denied("monitor_state_unavailable")
        if (type(state["catalog_calls_since_refresh"]) is not int or
                not 0 <= state["catalog_calls_since_refresh"] <= 2):
            raise Denied("monitor_state_unavailable")
        checkpoint = state["catalog_checkpoint"]
        if checkpoint is not None:
            checkpoint_fields = {"offset_id", "offset_date", "peer_kind", "peer_id", "access_hash"}
            if not isinstance(checkpoint, dict) or set(checkpoint) != checkpoint_fields:
                raise Denied("monitor_state_unavailable")
            if (type(checkpoint["offset_id"]) is not int or not 1 <= checkpoint["offset_id"] < 2**31 or
                    type(checkpoint["offset_date"]) is not int or not 0 <= checkpoint["offset_date"] < 2**53 or
                    checkpoint["peer_kind"] not in {"user", "channel", "chat", "self"}):
                raise Denied("monitor_state_unavailable")
            peer_id, access_hash = checkpoint["peer_id"], checkpoint["access_hash"]
            if checkpoint["peer_kind"] == "self":
                if peer_id is not None or access_hash is not None:
                    raise Denied("monitor_state_unavailable")
            elif (type(peer_id) is not int or not 1 <= peer_id < 2**63 or
                  (checkpoint["peer_kind"] in {"user", "channel"} and
                   (type(access_hash) is not int or not -(2**63) <= access_hash < 2**63)) or
                  (checkpoint["peer_kind"] == "chat" and access_hash is not None)):
                raise Denied("monitor_state_unavailable")
        delivery = state["inflight"]
        if delivery is not None:
            delivery_fields = {"in_cursor", "out_cursor", "peer", "after_id", "through_id",
                               "limit", "ack_id", "has_more"}
            if not isinstance(delivery, dict) or set(delivery) != delivery_fields:
                raise Denied("monitor_state_unavailable")
            for name in ("in_cursor", "out_cursor"):
                value = delivery[name]
                if value is not None and (not isinstance(value, str) or not 1 <= len(value) <= 128):
                    raise Denied("monitor_state_unavailable")
            peer = delivery["peer"]
            if peer is not None and (type(peer) is not int or not -(2**53) <= peer <= 2**53):
                raise Denied("monitor_state_unavailable")
            for name in ("after_id", "through_id", "ack_id"):
                value = delivery[name]
                if value is not None and (type(value) is not int or not 0 <= value < 2**31):
                    raise Denied("monitor_state_unavailable")
            if type(delivery["limit"]) is not int or not 1 <= delivery["limit"] <= 10:
                raise Denied("monitor_state_unavailable")
            if type(delivery["has_more"]) is not bool:
                raise Denied("monitor_state_unavailable")
            if delivery["peer"] is None and any(delivery[k] is not None for k in
                    ("after_id", "through_id", "ack_id")):
                raise Denied("monitor_state_unavailable")
            if delivery["peer"] is not None and any(delivery[k] is None for k in
                    ("after_id", "through_id", "ack_id")):
                raise Denied("monitor_state_unavailable")
        try:
            encoded = json.dumps(state, ensure_ascii=True, allow_nan=False,
                                 separators=(",", ":"))
        except (TypeError, ValueError):
            raise Denied("monitor_state_unavailable") from None
        if len(encoded) > 16_384:
            raise Denied("monitor_state_unavailable")
        return state

    def load_monitor_state(self):
        row = self.db.execute("SELECT state FROM monitor_state WHERE id=1").fetchone()
        if row is None:
            return self._default_monitor_state()
        try:
            state = json.loads(row[0])
            return self._validate_monitor_state(state)
        except (TypeError, ValueError, json.JSONDecodeError, Denied):
            raise Denied("monitor_state_unavailable") from None

    def save_monitor_state(self, state):
        state = self._validate_monitor_state(state)
        encoded = json.dumps(state, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        self.db.execute("INSERT OR REPLACE INTO monitor_state VALUES(1, ?)", (encoded,))
        self.db.commit()

    def observe_monitor_dialogs(self, rows, *, prioritize_new=False):
        """Persist bounded catalogue observations and enqueue unseen message ranges."""
        if not isinstance(rows, (list, tuple)) or len(rows) > 50:
            raise Denied("monitor_state_unavailable")
        parsed = []
        for row in rows:
            if not isinstance(row, dict):
                raise Denied("monitor_state_unavailable")
            peer, peer_type = row.get("peer_id"), row.get("type")
            latest = row.get("latest_message_id")
            if (type(peer) is not int or not -(2**53) <= peer <= 2**53 or
                    not isinstance(peer_type, str) or peer_type not in {"user", "group"}):
                continue
            latest = latest if type(latest) is int and 0 <= latest < 2**31 else 0
            parsed.append((peer, peer_type, latest))
        self.db.execute("BEGIN IMMEDIATE")
        try:
            for peer, peer_type, latest in parsed:
                checkpoint = self.db.execute(
                    "SELECT message_id FROM monitor_checkpoints WHERE peer=?", (peer,)).fetchone()
                if checkpoint is None:
                    # An empty dialog needs no checkpoint yet. If it becomes
                    # active before the next catalogue pass, bootstrap it then
                    # rather than treating its whole accumulated history as new.
                    if latest == 0:
                        continue
                    if peer_type == "user":
                        # Include a small recent window irrespective of Telegram's
                        # read watermark: read messages can still be unanswered.
                        baseline = max(0, latest - self.MONITOR_FIRST_DM_WINDOW_MESSAGES)
                        limited = int(baseline > 0)
                    else:
                        # Avoid exporting an old group backlog on first sight.
                        baseline, limited = latest, 0
                    self.db.execute(
                        "INSERT INTO monitor_checkpoints(peer,message_id,peer_type,initial_window_limited) VALUES(?,?,?,?)",
                        (peer, baseline, peer_type, limited))
                    checkpoint_id = baseline
                else:
                    checkpoint_id = checkpoint[0]
                if latest <= checkpoint_id:
                    continue
                pending = self.db.execute(
                    "SELECT sequence,after_id,through_id,priority FROM monitor_pending WHERE peer=?", (peer,)).fetchone()
                if pending is None:
                    self.db.execute(
                        "INSERT INTO monitor_pending(peer,after_id,through_id,peer_type,priority) VALUES(?,?,?,?,?)",
                        (peer, checkpoint_id, latest, peer_type,
                         int(prioritize_new or checkpoint is not None)))
                else:
                    if latest > pending[2]:
                        self.db.execute(
                            "UPDATE monitor_pending SET through_id=?,priority=1 WHERE peer=?",
                            (latest, peer))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def next_monitor_pending(self):
        row = self.db.execute(
            "SELECT peer,after_id,through_id,peer_type FROM monitor_pending "
            "ORDER BY priority DESC,sequence LIMIT 1").fetchone()
        return (None if row is None else
                {"peer_id": row[0], "after_id": row[1], "through_id": row[2], "peer_type": row[3]})

    def monitor_pending_count(self):
        return self.db.execute("SELECT count(*) FROM monitor_pending").fetchone()[0]

    def monitor_initial_window_limited_count(self):
        return self.db.execute(
            "SELECT count(*) FROM monitor_checkpoints WHERE initial_window_limited=1").fetchone()[0]

    def acknowledge_monitor_page(self, state, delivery):
        """Commit one delivered page only when its returned cursor is presented."""
        state = self._validate_monitor_state(state)
        if (state.get("inflight") != delivery or delivery is None or
                not isinstance(delivery.get("out_cursor"), str)):
            raise Denied("invalid_cursor")
        self.db.execute("BEGIN IMMEDIATE")
        try:
            stored = self.db.execute("SELECT state FROM monitor_state WHERE id=1").fetchone()
            current = self._default_monitor_state() if stored is None else self._validate_monitor_state(
                json.loads(stored[0]))
            if current.get("inflight") != delivery:
                raise Denied("invalid_cursor")
            peer, ack_id = delivery["peer"], delivery["ack_id"]
            if peer is not None:
                checkpoint = self.db.execute(
                    "SELECT message_id,peer_type FROM monitor_checkpoints WHERE peer=?", (peer,)).fetchone()
                previous = checkpoint[0] if checkpoint else 0
                pending = self.db.execute(
                    "SELECT sequence,after_id,through_id,peer_type FROM monitor_pending WHERE peer=?",
                    (peer,)).fetchone()
                peer_type = checkpoint[1] if checkpoint else (pending[3] if pending else "user")
                self.db.execute(
                    "INSERT INTO monitor_checkpoints(peer,message_id,peer_type) VALUES(?,?,?) "
                    "ON CONFLICT(peer) DO UPDATE SET message_id=MAX(monitor_checkpoints.message_id,excluded.message_id), "
                    "peer_type=excluded.peer_type",
                    (peer, max(previous, ack_id), peer_type))
                if pending is not None:
                    _, current_after, current_through, peer_type = pending
                    if delivery["has_more"] or current_through > delivery["through_id"]:
                        sequence = self.db.execute(
                            "SELECT COALESCE(MAX(sequence),0)+1 FROM monitor_pending").fetchone()[0]
                        self.db.execute("UPDATE monitor_pending SET after_id=?,sequence=? WHERE peer=?",
                                        (max(current_after, ack_id), sequence, peer))
                    else:
                        self.db.execute("DELETE FROM monitor_pending WHERE peer=?", (peer,))
            current["inflight"] = None
            current["last_acked_cursor"] = delivery["out_cursor"]
            encoded = json.dumps(current, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
            self.db.execute("INSERT OR REPLACE INTO monitor_state VALUES(1,?)", (encoded,))
            self.db.commit()
            return current
        except BaseException:
            self.db.rollback()
            raise

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
