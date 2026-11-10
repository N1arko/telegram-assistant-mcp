"""Dependency-free restricted service, injectable backend for offline testing."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import re
import secrets
import sys
import time
from collections import OrderedDict
from contextvars import ContextVar
from pathlib import Path
from urllib.parse import urlsplit

from . import diagnostics
from .security import Denied, Policy, Quotas, RateGate, integer, peer_id as validate_peer_id
from .media import (AudioResult, ImageResult, MAX_AUDIO_INPUT_BYTES, MAX_INLINE_AUDIO_BYTES,
                    MAX_AUDIO_RESPONSE_BYTES, MAX_IMAGE_PREVIEW_BYTES, MAX_IMAGE_INPUT_BYTES,
                    MAX_DOCUMENT_INPUT_BYTES, MAX_DOCUMENT_TEXT_CHARS, MAX_MEDIA_RESPONSE_BYTES,
                    MEDIA_TIMEOUT_SECONDS, MediaCache, DocumentText,
                    PDF_WORKER_OUTPUT_BYTES, PDF_WORKER_TIMEOUT_SECONDS,
                    MAX_TRANSCRIPT_CHARS, TranscriptionConfig, prepare_audio, preview_image,
                    sniff_audio_kind, extract_document_text, temporary_media_dir, prepare_outbound_media,
                    MAX_OUTBOUND_ITEMS, MAX_OUTBOUND_MEDIA_BYTES, _run_bounded)

SCOPES: ContextVar[frozenset[str]] = ContextVar("telegram_assistant_scopes", default=frozenset())
MAX_BYTES = 48 * 1024
EXACT_POST_TEXT_CHARS = 4000
MEDIA_SEND_TIMEOUT_SECONDS = 120
READ_OPERATIONS = frozenset({
    "list_dialogs", "get_history", "search_messages", "get_reply_context",
    "list_forum_topics", "get_forum_topic", "scan_updates", "view_photo", "get_audio",
    "read_document", "transcribe_audio", "read_channel", "list_public_channels",
})
WRITE_OPERATIONS = frozenset({"send_message", "send_media"})
SUPPORTED_OPERATIONS = READ_OPERATIONS | WRITE_OPERATIONS
MEDIA_OPERATIONS = frozenset({"view_photo", "get_audio", "read_document", "transcribe_audio"})
CHANNEL_USERNAME = re.compile(r"^[A-Za-z0-9_]{5,32}$", re.ASCII)


def parse_channel_reference(reference):
    """Accept one public @username or t.me post link; never resolve invite links."""
    if not isinstance(reference, str) or len(reference) > 2048:
        raise Denied("invalid_channel_reference")
    value = reference.strip()
    if not value:
        raise Denied("invalid_channel_reference")

    post_id = None
    if "://" in value:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError:
            raise Denied("invalid_channel_reference") from None
        if (parsed.scheme != "https" or parsed.hostname not in {"t.me", "telegram.me"} or
                parsed.username is not None or parsed.password is not None or port is not None or
                parsed.fragment or parsed.query not in {"", "single"}):
            raise Denied("invalid_channel_reference")
        parts = parsed.path.strip("/").split("/")
        if parts and parts[0] == "s":
            parts = parts[1:]
        if not parts or parts[0] in {"c", "joinchat"} or parts[0].startswith("+") or len(parts) > 2:
            raise Denied("invalid_channel_reference")
        username = parts[0]
        if len(parts) == 2:
            if not parts[1].isascii() or not parts[1].isdigit():
                raise Denied("invalid_channel_reference")
            post_id = int(parts[1])
            if not 1 <= post_id < 2**31:
                raise Denied("invalid_channel_reference")
    else:
        username = value[1:] if value.startswith("@") else value
        if any(char in username for char in "/:?#[\\]@"):
            raise Denied("invalid_channel_reference")

    if not CHANNEL_USERNAME.fullmatch(username):
        raise Denied("invalid_channel_reference")
    return username, post_id


def clip(value, limit=200):
    text = str(value or "")
    return text[:limit], len(text) > limit


def encode_response(payload):
    # Remove whole tail records if JSON exceeds budget; always return a cursor
    # at the last emitted message rather than skipping unseen records.
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def wire_size(payload):
    # Account for escaping when compact JSON is carried in MCP TextContent,
    # plus a conservative JSON-RPC envelope allowance.
    body = {"content": [{"type": "text", "text": encode_response(payload).decode("utf-8")}],
            "isError": bool(payload.get("error"))}
    return len(json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")) + 256


def bounded(payload):
    if wire_size(payload) > MAX_BYTES:
        raise Denied("response_too_large")
    return payload


class Service:
    def __init__(self, backend, policy: Policy | None = None, quotas: Quotas | None = None,
                 *, gate=None, clock=time.time, read_only_broadcast_channel=None,
                 targeted_channel_reads_enabled=False,
                 transcription: TranscriptionConfig | None = None, transcriber=None,
                 media_cache=None):
        self.backend = backend
        self.policy = policy or Policy()
        self.quotas = quotas
        self.gate = gate or RateGate()
        self.clock = clock
        self.read_only_broadcast_channel = read_only_broadcast_channel
        if type(targeted_channel_reads_enabled) is not bool:
            raise ValueError("targeted_channel_reads_enabled must be a bool")
        self.targeted_channel_reads_enabled = targeted_channel_reads_enabled
        self.transcription = transcription or TranscriptionConfig()
        self.transcriber = transcriber
        self.media_cache = media_cache or MediaCache()
        self.lock = asyncio.Lock()
        self.snapshots = OrderedDict()
        self.cursors = OrderedDict()
        self.public_channel_snapshots = OrderedDict()
        self.public_channel_cursors = OrderedDict()
        self._send_attempted = False

    async def invoke(self, operation, *args, **kwargs):
        # Tool annotations are hints, not authorization.
        if "telegram:read" not in SCOPES.get():
            return {"error": "unauthorized"}
        if operation not in SUPPORTED_OPERATIONS:
            return {"error": "unknown_tool"}
        if operation in {"read_channel", "list_public_channels"} and not self.targeted_channel_reads_enabled:
            return {"error": "channel_reads_disabled"}
        async with self.lock:
            diagnostics.state.set({"stage": "operation"})
            self._send_attempted = False
            try:
                self.gate.check(count_local=operation not in READ_OPERATIONS)
                timeout = (MEDIA_SEND_TIMEOUT_SECONDS if operation == "send_media" else
                           MEDIA_TIMEOUT_SECONDS if operation in MEDIA_OPERATIONS else 20)
                result = await asyncio.wait_for(getattr(self, operation)(*args, **kwargs), timeout)
                if isinstance(result, ImageResult):
                    if (not isinstance(result.data, bytes) or result.mime_type != "image/jpeg" or
                            len(result.data) > MAX_IMAGE_PREVIEW_BYTES or
                            ((len(result.data) + 2) // 3) * 4 + 8192 > MAX_MEDIA_RESPONSE_BYTES):
                        raise Denied("image_preview_too_large")
                    return result
                if isinstance(result, AudioResult):
                    if (not isinstance(result.data, bytes) or len(result.data) > MAX_INLINE_AUDIO_BYTES or
                            result.mime_type not in {"audio/ogg", "audio/mpeg", "audio/mp4",
                                                     "audio/wav", "audio/webm"} or
                            ((len(result.data) + 2) // 3) * 4 + 8192 > MAX_AUDIO_RESPONSE_BYTES):
                        raise Denied("audio_response_too_large")
                    return result
                result = bounded(result)
                diagnostics.record(operation, self.backend, "success")
                return result
            except Denied as exc:
                diagnostics.record(operation, self.backend, "denied", exc)
                result = {"error": exc.code}
                if exc.retry_after is not None:
                    result["retry_after_seconds"] = exc.retry_after
                return result
            except TimeoutError as exc:
                diagnostics.record(operation, self.backend, "timeout", exc)
                return {"error": ("delivery_unknown" if self._send_attempted else "send_preflight_unavailable")
                        if operation in {"send_message", "send_media"} else
                        ("media_timeout" if operation in MEDIA_OPERATIONS else "telegram_timeout")}
            except Exception as exc:
                diagnostics.record(operation, self.backend, "exception", exc)
                # Inspect structured flood fields only; never return/log repr or args.
                if type(exc).__name__ in {"FloodWaitError", "SlowModeWaitError", "FloodPremiumWaitError"}:
                    seconds = max(1, int(getattr(exc, "seconds", 60)))
                    self.gate.flood(seconds)
                    return {"error": "telegram_rate_limited", "retry_after_seconds": seconds}
                if (operation == "read_channel" and type(exc).__name__ in {
                        "ChannelPrivateError", "ChannelInvalidError", "PeerIdInvalidError",
                        "UsernameInvalidError", "UsernameNotOccupiedError"}):
                    return {"error": "channel_not_accessible"}
                if operation in {"send_message", "send_media"}:
                    name = type(exc).__name__
                    if name in {"ChatWriteForbiddenError", "ChatAdminRequiredError",
                                "UserBannedInChannelError", "ChatSendPlainForbiddenError"}:
                        return {"error": "telegram_write_forbidden"}
                    if name in {"TopicClosedError", "TopicDeletedError"}:
                        return {"error": "topic_unavailable"}
                    if name in {"PeerIdInvalidError", "ReplyMessageIdInvalidError"}:
                        return {"error": "telegram_address_invalid"}
                return {"error": ("delivery_unknown" if self._send_attempted else "send_preflight_unavailable")
                        if operation in {"send_message", "send_media"} else
                        ("media_unavailable" if operation in MEDIA_OPERATIONS else "telegram_unavailable")}

    async def view_photo(self, peer_id, message_id):
        integer(message_id, 1, 2**31 - 1)
        target = await self._resolve(peer_id, allow_broadcast=True)
        key = ("photo", target, message_id)
        cached = self.media_cache.get(key)
        if cached is not None:
            return cached
        fetch = getattr(self.backend, "fetch_media_file", None)
        if fetch is None:
            raise Denied("media_unavailable")
        with temporary_media_dir() as directory:
            path = Path(directory) / "telegram-photo"
            await fetch(target, message_id, kind="photo", destination=path,
                        max_bytes=MAX_IMAGE_INPUT_BYTES)
            result = await preview_image(path)
        self.media_cache.put(key, result)
        return result

    async def get_audio(self, peer_id, message_id):
        integer(message_id, 1, 2**31 - 1)
        target = await self._resolve(peer_id, allow_broadcast=True)
        fetch = getattr(self.backend, "fetch_media_file", None)
        if fetch is None:
            raise Denied("media_unavailable")
        with temporary_media_dir() as directory:
            source = Path(directory) / "telegram-audio"
            metadata = await fetch(target, message_id, kind="audio", destination=source,
                                   max_bytes=MAX_INLINE_AUDIO_BYTES)
            kind = sniff_audio_kind(source)
            declared_mime = metadata.get("declared_mime") if isinstance(metadata, dict) else None
            self._check_audio_mime(kind, declared_mime)
            mime_type = {"ogg-opus": "audio/ogg", "mp3": "audio/mpeg", "mp4": "audio/mp4",
                         "wav": "audio/wav", "webm": "audio/webm"}[kind]
            return AudioResult(source.read_bytes(), mime_type)

    async def read_document(self, peer_id, message_id, text_offset=0,
                            text_limit=MAX_DOCUMENT_TEXT_CHARS, expected_document_sha256=None):
        integer(message_id, 1, 2**31 - 1)
        integer(text_offset, 0, 2**31 - 1)
        integer(text_limit, 1, MAX_DOCUMENT_TEXT_CHARS)
        if expected_document_sha256 is not None and (
                type(expected_document_sha256) is not str or len(expected_document_sha256) != 64 or
                any(char not in "0123456789abcdef" for char in expected_document_sha256)):
            raise Denied("invalid_argument")
        target = await self._resolve(peer_id, allow_broadcast=True)
        fetch = getattr(self.backend, "fetch_media_file", None)
        if fetch is None:
            raise Denied("media_unavailable")
        with temporary_media_dir() as directory:
            source = Path(directory) / "telegram-document"
            metadata = await fetch(target, message_id, kind="document", destination=source,
                                  max_bytes=MAX_DOCUMENT_INPUT_BYTES)
            declared_mime = metadata.get("declared_mime") if isinstance(metadata, dict) else None
            with source.open("rb") as downloaded:
                document_sha256 = hashlib.file_digest(downloaded, "sha256").hexdigest()
                if expected_document_sha256 is not None and document_sha256 != expected_document_sha256:
                    raise Denied("document_changed")
                downloaded.seek(0)
                is_pdf = b"%PDF-" in downloaded.read(1024)
            if is_pdf:
                document = await self._extract_pdf_in_worker(
                    source, text_offset=text_offset, text_limit=text_limit)
            else:
                document = await asyncio.to_thread(
                    extract_document_text, source, declared_mime=declared_mime,
                    max_chars=text_limit, text_offset=text_offset)
        def payload(length):
            text = document.text[:length]
            has_more = document.truncated or length < len(document.text)
            return {"peer_id": target, "message_id": message_id,
                    "document_type": document.document_type, "pages": document.pages,
                    "text": text, "text_available": bool(text.strip()),
                    "text_truncated": has_more, "text_offset": text_offset,
                    "text_next_offset": text_offset + len(text) if has_more else None,
                    "text_complete": text_offset == 0 and not has_more,
                    "document_sha256": document_sha256, "untrusted_content": True}
        # JSON escaping can consume more than the character limit suggests.
        # Shorten this page only, preserving every remaining character for the next.
        low, high = 0, len(document.text)
        while low < high:
            middle = (low + high + 1) // 2
            if wire_size(payload(middle)) <= MAX_BYTES:
                low = middle
            else:
                high = middle - 1
        return payload(low)

    @staticmethod
    async def _extract_pdf_in_worker(path, *, text_offset=0, text_limit=MAX_DOCUMENT_TEXT_CHARS):
        integer(text_offset, 0, 2**31 - 1)
        integer(text_limit, 1, MAX_DOCUMENT_TEXT_CHARS)
        try:
            stdout = await _run_bounded(
                [sys.executable, "-m", "telegram_assistant.pdf_worker", str(path),
                 str(text_offset), str(text_limit)],
                timeout=PDF_WORKER_TIMEOUT_SECONDS, max_stdout=PDF_WORKER_OUTPUT_BYTES)
        except Denied as exc:
            code = {"media_processor_unavailable": "document_parser_unavailable",
                    "media_processing_timeout": "document_parse_timeout"}.get(
                        exc.code, "document_parse_failed")
            raise Denied(code) from None
        try:
            result = json.loads(stdout)
        except (ValueError, UnicodeError):
            raise Denied("document_parse_failed") from None
        if not isinstance(result, dict):
            raise Denied("document_parse_failed")
        error = result.get("error")
        if isinstance(error, str) and error in {
                "document_encrypted", "document_too_many_pages", "document_parser_unavailable",
                "document_parse_failed", "document_isolation_unavailable"}:
            raise Denied(error)
        text, pages, truncated = result.get("text"), result.get("pages"), result.get("truncated")
        if (not isinstance(text, str) or len(text) > text_limit or (truncated and not text) or type(pages) is not int or
                not 0 <= pages <= 100 or type(truncated) is not bool):
            raise Denied("document_parse_failed")
        return DocumentText(text, "pdf", pages=pages, truncated=truncated)

    @staticmethod
    def _check_audio_mime(kind, declared_mime):
        if declared_mime is None:
            return
        if not isinstance(declared_mime, str) or len(declared_mime) > 96:
            raise Denied("audio_mime_mismatch")
        declared = declared_mime.strip().lower().split(";", 1)[0]
        accepted = {
            "ogg-opus": {"audio/ogg", "application/ogg", "audio/opus", "application/octet-stream"},
            "mp3": {"audio/mpeg", "audio/mp3", "audio/x-mp3", "application/octet-stream"},
            "mp4": {"audio/mp4", "audio/m4a", "audio/x-m4a", "video/mp4", "application/octet-stream"},
            "wav": {"audio/wav", "audio/x-wav", "audio/wave", "application/octet-stream"},
            "webm": {"audio/webm", "video/webm", "application/octet-stream"},
        }
        if declared not in accepted[kind]:
            raise Denied("audio_mime_mismatch")

    async def transcribe_audio(self, peer_id, message_id):
        if self.transcription.provider != "openai" or self.transcriber is None:
            raise Denied("transcription_disabled")
        integer(message_id, 1, 2**31 - 1)
        target = await self._resolve(peer_id, allow_broadcast=True)
        key = ("transcript", target, message_id, "openai", self.transcription.max_duration_seconds)
        cached = self.media_cache.get(key)
        if cached is not None:
            text, transcript_truncated = cached
            return {"peer_id": target, "message_id": message_id, "transcript": text,
                    "transcript_truncated": transcript_truncated, "untrusted_content": True,
                    "provider": "openai", "cached": True}
        fetch = getattr(self.backend, "fetch_media_file", None)
        if fetch is None:
            raise Denied("media_unavailable")
        with temporary_media_dir() as directory:
            workdir = Path(directory)
            source = workdir / "telegram-audio"
            metadata = await fetch(target, message_id, kind="audio", destination=source,
                                   max_bytes=MAX_AUDIO_INPUT_BYTES)
            declared_duration = metadata.get("declared_duration") if isinstance(metadata, dict) else None
            if type(declared_duration) is not int or not 1 <= declared_duration <= self.transcription.max_duration_seconds:
                raise Denied("audio_too_long" if type(declared_duration) is int else "audio_duration_unavailable")
            actual_kind = sniff_audio_kind(source)
            self._check_audio_mime(actual_kind, metadata.get("declared_mime"))
            upload, filename, mime_type, duration = await prepare_audio(
                source, workdir, max_seconds=self.transcription.max_duration_seconds)
            if duration > self.transcription.max_duration_seconds:
                raise Denied("audio_too_long")
            billable_seconds = max(1, math.ceil(duration))
            if self.transcription.monthly_seconds:
                if self.quotas is None:
                    raise Denied("transcription_budget_unavailable")
                try:
                    self.quotas.reserve_transcription(
                        billable_seconds, self.transcription.monthly_seconds, self.clock())
                except Denied:
                    raise
                except Exception:
                    raise Denied("transcription_budget_unavailable") from None
            try:
                transcript = await self.transcriber.transcribe(
                    upload, filename=filename, mime_type=mime_type)
            except Denied:
                raise
            except Exception:
                raise Denied("transcription_provider_error") from None
        if not isinstance(transcript, str):
            raise Denied("transcription_provider_error")
        transcript_truncated = len(transcript) > MAX_TRANSCRIPT_CHARS
        transcript = transcript[:MAX_TRANSCRIPT_CHARS]
        self.media_cache.put(key, (transcript, transcript_truncated))
        return {"peer_id": target, "message_id": message_id, "transcript": transcript,
                "transcript_truncated": transcript_truncated, "untrusted_content": True,
                "provider": "openai", "cached": False}

    async def _resolve(self, target, *, allow_broadcast=False, return_type=False):
        target = validate_peer_id(target)
        allowed_peer_id = (self.read_only_broadcast_channel[0]
                           if self.read_only_broadcast_channel is not None else None)
        # This exact channel is read-only. Do not let send_message inherit the
        # read exception, even if a future technical send grant is introduced.
        if target == allowed_peer_id and not allow_broadcast:
            raise Denied("peer_mismatch")
        resolved = await self.backend.resolve(target)
        if resolved[0] != target:
            raise Denied("peer_mismatch")
        if target == allowed_peer_id:
            if not allow_broadcast or resolved[1] != "broadcast_channel":
                raise Denied("peer_mismatch")
            return (target, resolved[1]) if return_type else target
        if resolved[1] not in {"user", "group"}:
            raise Denied("peer_mismatch")
        return (target, resolved[1]) if return_type else target

    async def list_dialogs(self, archived=None, limit=20, cursor=None, *,
                           _monitor_metadata=False, _fresh=False, _checkpoint=None):
        integer(limit, 1, 50)
        if archived is not None and type(archived) is not bool:
            raise Denied("invalid_argument")
        now = self.clock()
        for key in list(self.snapshots):
            if self.snapshots[key]['expires'] <= now:
                del self.snapshots[key]
        if cursor is not None:
            if not isinstance(cursor, str) or len(cursor) > 128 or cursor not in self.cursors:
                raise Denied("invalid_cursor")
            snap, block_index, start, expected = self.cursors[cursor]
            if expected != archived or snap not in self.snapshots:
                raise Denied("cursor_expired_or_mismatched")
        else:
            # Reuse the cached prefix across chats instead of restarting a
            # Telegram catalogue scan on each initial request.
            snap = None if _fresh else next((key for key, value in reversed(self.snapshots.items())
                                             if value['archived'] == archived and
                                             value.get('monitor', False) == _monitor_metadata), None)
            if snap is None:
                snap = secrets.token_urlsafe(24)
                start = self.backend.start_dialogs
                if _checkpoint is not None:
                    dialog_state = start(archived, checkpoint=_checkpoint)
                else:
                    dialog_state = start(archived)
                self.snapshots[snap] = {'expires': now + (7 * 24 * 60 * 60 if _monitor_metadata else 300),
                                        'archived': archived, 'monitor': _monitor_metadata,
                                        'state': dialog_state, 'blocks': []}
                while len(self.snapshots) > 4:
                    self.snapshots.popitem(last=False)
            block_index, start = 0, 0
        listing = self.snapshots[snap]
        if block_index == len(listing['blocks']):
            result = await self.backend.dialog_page(listing['state'], limit)
            rows = []
            allowed_peer_id = (self.read_only_broadcast_channel[0]
                               if self.read_only_broadcast_channel is not None else None)
            for d in result['rows']:
                configured_peer = d["peer_id"] == allowed_peer_id
                is_owner_broadcast = configured_peer and d["type"] == "broadcast_channel"
                # The recurring personal/work-chat scanner never inherits the
                # one-off owner-channel exception. Channel monitoring requires
                # a separate, explicit feature and allowlist.
                if _monitor_metadata and is_owner_broadcast:
                    continue
                if ((configured_peer and not is_owner_broadcast) or
                        (d["type"] not in {"user", "group"} and not is_owner_broadcast) or
                        (archived is not None and d["archived"] != archived)):
                    continue
                title, truncated = clip(d["title"])
                rows.append({"peer_id": d["peer_id"], "title": title, "title_truncated": truncated,
                             "type": "channel" if is_owner_broadcast else d["type"],
                             "archived": d["archived"], "unread": d["unread"],
                             "latest_message_id": d.get("latest_message_id"),
                             "latest_message_date": d.get("latest_message_date"),
                             "read_inbox_max_id": d.get("read_inbox_max_id", 0)})
            listing['blocks'].append({'rows': rows, 'done': result['done'], 'truncated': result['truncated']})
        block = listing['blocks'][block_index]
        rows = block['rows']
        page = rows[start:start + limit]
        if not _monitor_metadata:
            page = [{key: row[key] for key in
                     ("peer_id", "title", "title_truncated", "type", "archived", "unread")}
                    for row in page]
        payload = {"dialogs": page, "next_cursor": None, "snapshot_expires_at": listing['expires'],
                   "listing_complete": False, "scan_truncated": block['truncated'],
                   "pagination_consistency": "cached_pages_stable_unfetched_live", "untrusted_content": True}
        while wire_size(payload) > MAX_BYTES - 64 and page:
            page.pop()
        end = start + len(page)
        if end < len(rows) or not block['done']:
            token = secrets.token_urlsafe(24)
            next_block, next_start = (block_index, end) if end < len(rows) else (block_index + 1, 0)
            self.cursors[token] = (snap, next_block, next_start, archived)
            payload["next_cursor"] = token
            while len(self.cursors) > 256:
                self.cursors.popitem(last=False)
        payload['listing_complete'] = payload['next_cursor'] is None and block['done'] and not block['truncated']
        if _monitor_metadata:
            checkpoint = None
            get_checkpoint = getattr(self.backend, "dialog_checkpoint", None)
            if payload["next_cursor"] is not None and get_checkpoint is not None:
                checkpoint = get_checkpoint(listing["state"])
            payload["monitor_checkpoint"] = checkpoint
        return payload

    def _monitor_output(self, messages, delivery, state, pending_count):
        limited_dialogs = self.quotas.monitor_initial_window_limited_count()
        return {"messages": messages, "next_cursor": delivery["out_cursor"],
                "catalogue_complete": state["catalog_complete"],
                "scan_truncated": state["catalog_truncated"],
                "coverage_restarted": state["coverage_restarted"],
                "queued_peers": pending_count,
                "initial_window_messages": self.quotas.MONITOR_FIRST_DM_WINDOW_MESSAGES,
                "initial_window_limited_dialogs": limited_dialogs,
                "initial_history_incomplete": limited_dialogs > 0,
                "coverage_complete": (state["catalog_finished"] and state["catalog_complete"] and
                                      pending_count == 0),
                "untrusted_content": True,
                "continuation": "pass next_cursor to acknowledge this page; reuse the same input cursor to replay it"}

    async def _monitor_records(self, delivery):
        if delivery["peer"] is None:
            return []
        target, peer_type = await self._resolve(delivery["peer"], return_type=True)
        if peer_type not in {"user", "group"}:
            raise Denied("peer_mismatch")
        fetch = getattr(self.backend, "new_messages", None)
        if fetch is None:
            raise Denied("monitor_unavailable")
        rows = await fetch(target, after_id=delivery["after_id"],
                           through_id=delivery["through_id"], limit=delivery["limit"])
        return [self._record(row, target) for row in rows[:delivery["limit"]]]

    async def scan_updates(self, limit=5, cursor=None):
        """Incrementally scan a bounded dialog page and deliver one peer's new messages."""
        integer(limit, 1, 10)
        if cursor is not None and (not isinstance(cursor, str) or not 1 <= len(cursor) <= 128):
            raise Denied("invalid_cursor")
        if self.quotas is None:
            raise Denied("monitor_state_unavailable")
        state = self.quotas.load_monitor_state()
        delivery = state["inflight"]
        if delivery is not None:
            if cursor == delivery["in_cursor"]:
                messages = await self._monitor_records(delivery)
                payload = self._monitor_output(
                    messages, delivery, state, self.quotas.monitor_pending_count())
                while wire_size(payload) > MAX_BYTES and messages:
                    messages.pop()
                    if messages:
                        delivery["limit"] = len(messages)
                        delivery["ack_id"] = messages[-1]["message_id"]
                        delivery["has_more"] = True
                        state["inflight"] = delivery
                        self.quotas.save_monitor_state(state)
                    payload = self._monitor_output(
                        messages, delivery, state, self.quotas.monitor_pending_count())
                return bounded(payload)
            if cursor != delivery["out_cursor"]:
                raise Denied("invalid_cursor")
            state = self.quotas.acknowledge_monitor_page(state, delivery)
        elif cursor != state["last_acked_cursor"]:
            raise Denied("invalid_cursor")

        # Keep discovery moving while a large old queue drains, but cap the
        # catalogue at one RPC per three newly acknowledged scan calls. Empty
        # queues and small catalogues still finish a sweep as quickly as one
        # bounded page per call. New activity normally promotes its dialog to
        # Telegram's newest-dialog page, so this gives a three-call freshness
        # bound without spending one extra catalogue RPC on every backlog page.
        pending_before = self.quotas.monitor_pending_count()
        catalogue_due = (not state["sweep_started"] or pending_before == 0 or
                         state["catalog_calls_since_refresh"] >= 2)
        if catalogue_due:
            fresh = not state["sweep_started"]
            if state["catalog_finished"]:
                state.update({"catalog_cursor": None, "catalog_finished": False,
                              "catalog_complete": False, "catalog_truncated": False,
                              "catalog_checkpoint": None, "catalog_calls_since_refresh": 0,
                              "coverage_restarted": False, "sweep_started": True})
                fresh = True
                self.quotas.save_monitor_state(state)
            elif fresh:
                state["sweep_started"] = True
                self.quotas.save_monitor_state(state)

            try:
                listing = await self.list_dialogs(
                    archived=None, limit=50, cursor=state["catalog_cursor"],
                    _monitor_metadata=True, _fresh=fresh,
                    _checkpoint=(state["catalog_checkpoint"]
                                 if state["catalog_cursor"] is None else None))
            except Denied as exc:
                if (state["catalog_cursor"] is None or
                        exc.code not in {"invalid_cursor", "cursor_expired_or_mismatched"}):
                    raise
                # The in-memory snapshot cursor is only a fast path. Resume from
                # the last stable Telethon offset persisted with monitor state,
                # or restart from page one if a backend cannot provide one.
                checkpoint = state["catalog_checkpoint"]
                state.update({"catalog_cursor": None, "catalog_finished": False,
                              "catalog_complete": False, "catalog_truncated": False,
                              "catalog_calls_since_refresh": 0,
                              "coverage_restarted": checkpoint is None, "sweep_started": True})
                if checkpoint is None:
                    state["catalog_checkpoint"] = None
                self.quotas.save_monitor_state(state)
                listing = await self.list_dialogs(archived=None, limit=50, cursor=None,
                                                  _monitor_metadata=True, _fresh=True,
                                                  _checkpoint=checkpoint)

            self.quotas.observe_monitor_dialogs(
                listing["dialogs"], prioritize_new=state["catalog_sweeps_completed"])
            state["catalog_cursor"] = listing["next_cursor"]
            state["catalog_finished"] = listing["next_cursor"] is None
            state["catalog_complete"] = bool(listing["listing_complete"])
            state["catalog_truncated"] = state["catalog_truncated"] or bool(listing["scan_truncated"])
            if state["catalog_finished"] and state["catalog_complete"]:
                state["catalog_sweeps_completed"] = True
            if state["catalog_finished"]:
                state["catalog_checkpoint"] = None
            elif listing.get("monitor_checkpoint") is not None:
                state["catalog_checkpoint"] = listing["monitor_checkpoint"]
            state["catalog_calls_since_refresh"] = 0
            self.quotas.save_monitor_state(state)
        else:
            state["catalog_calls_since_refresh"] += 1
            self.quotas.save_monitor_state(state)

        pending = self.quotas.next_monitor_pending()
        messages = []
        peer = after_id = through_id = ack_id = None
        has_more = False
        if pending is not None:
            peer = pending["peer_id"]
            after_id, through_id = pending["after_id"], pending["through_id"]
            target, peer_type = await self._resolve(peer, return_type=True)
            if peer_type != pending["peer_type"]:
                raise Denied("peer_mismatch")
            fetch = getattr(self.backend, "new_messages", None)
            if fetch is None:
                raise Denied("monitor_unavailable")
            fetched = await fetch(target, after_id=after_id, through_id=through_id, limit=limit)
            page = list(fetched[:limit])
            has_more = len(fetched) > len(page)

        delivery = {"in_cursor": cursor, "out_cursor": secrets.token_urlsafe(24),
                    "peer": peer, "after_id": after_id, "through_id": through_id,
                    "limit": max(1, len(page)) if pending is not None and page else limit,
                    "ack_id": ack_id, "has_more": has_more}
        while True:
            messages = [self._record(row, target) for row in page] if pending is not None else []
            if pending is not None and page:
                delivery["limit"] = len(page)
                delivery["has_more"] = has_more
                delivery["ack_id"] = page[-1]["id"] if has_more else through_id
            elif pending is not None:
                # A successful empty fetch covers the requested ID range. It
                # remains uncommitted until the caller presents this cursor.
                delivery["ack_id"] = through_id
            payload = self._monitor_output(
                messages, delivery, state, self.quotas.monitor_pending_count())
            if wire_size(payload) <= MAX_BYTES:
                break
            if pending is None or not page:
                raise Denied("monitor_response_too_large")
            page.pop()
            has_more = True
        state["inflight"] = delivery
        self.quotas.save_monitor_state(state)
        return bounded(payload)

    @staticmethod
    def _record(message, target, *, exact_text_offset=None):
        if exact_text_offset is None:
            text, truncated = clip(message["text"], 2000)
        else:
            full_text = str(message.get("text") or "")
            if exact_text_offset > len(full_text):
                raise Denied("invalid_text_offset")
            end = min(len(full_text), exact_text_offset + EXACT_POST_TEXT_CHARS)
            text = full_text[exact_text_offset:end]
            # `text_complete` means this single response contains the whole
            # post, starting at offset zero. `text_next_offset` independently
            # indicates whether another chunk remains.
            complete_text = exact_text_offset == 0 and end == len(full_text)
            truncated = not complete_text
        sender = message.get("sender_id")
        record = {"peer_id": target, "message_id": message["id"], "sender_id": sender,
                  "date": message.get("date"), "text": text, "text_truncated": truncated,
                  "has_media": bool(message.get("has_media")), "media_type": message.get("media_type"),
                  "reply_to": message.get("reply_to"),
                  "topic_id": message.get("topic_id"),
                  "reply_peer_id": message.get("reply_peer_id"), "out": bool(message.get("out", False))}
        if exact_text_offset is not None:
            record.update({"text_offset": exact_text_offset,
                           "text_complete": complete_text,
                           "text_next_offset": end if end < len(full_text) else None,
                           "text_total_chars": len(full_text)})
        return record

    async def get_forum_topic(self, peer_id, topic_id):
        integer(topic_id, 1, 2**31 - 1)
        target, peer_type = await self._resolve(peer_id, return_type=True)
        if peer_type != "group":
            raise Denied("not_forum_group")
        check_state = getattr(self.backend, "forum_state", None)
        if check_state is not None and not await check_state(target):
            raise Denied("not_forum_group")
        topic = await self.backend.forum_topic(target, topic_id)
        if topic is None:
            raise Denied("topic_missing")
        if topic["peer_id"] != target or topic["topic_id"] != topic_id:
            raise Denied("topic_peer_mismatch")
        if not topic["deleted"]:
            topic = dict(topic)
            topic["title"], topic["title_truncated"] = clip(topic["title"])
        return {"topic": topic, "untrusted_content": True}

    async def list_forum_topics(self, peer_id, limit=20, offset_date=None,
                                offset_id=0, offset_topic=0):
        integer(limit, 1, 50)
        if offset_date is not None:
            integer(offset_date, 1, 2**31 - 1)
        integer(offset_id, 0, 2**31 - 1)
        integer(offset_topic, 0, 2**31 - 1)
        if (offset_date is None) != (offset_id == 0) or (offset_id == 0) != (offset_topic == 0):
            raise Denied("invalid_topic_offset")
        target, peer_type = await self._resolve(peer_id, return_type=True)
        if peer_type != "group":
            raise Denied("not_forum_group")
        check_state = getattr(self.backend, "forum_state", None)
        if check_state is not None and not await check_state(target):
            raise Denied("not_forum_group")
        topics, next_offset, truncated = await self.backend.forum_topics(
            target, limit=limit, offset_date=offset_date,
            offset_id=offset_id, offset_topic=offset_topic)
        for topic in topics:
            if topic["peer_id"] != target:
                raise Denied("topic_peer_mismatch")
            if not topic["deleted"]:
                topic["title"], topic["title_truncated"] = clip(topic["title"])
        return {"topics": topics, "next_offset": next_offset, "scan_truncated": truncated,
                "untrusted_content": True}

    async def _topic_address(self, target, peer_type, topic_id, reply_to):
        check_state = getattr(self.backend, "forum_state", None)
        forum = (bool(await check_state(target)) if check_state is not None and peer_type == "group"
                 else bool(getattr(self.backend, "is_forum_group", lambda _target: False)(target)))
        if not forum:
            if topic_id is not None:
                raise Denied("not_forum_group")
            return reply_to
        if topic_id is None:
            raise Denied("topic_id_required")
        topic = await self.backend.forum_topic(target, topic_id)
        if topic is None or topic.get("deleted"):
            raise Denied("topic_missing")
        if topic.get("peer_id") != target or topic.get("topic_id") != topic_id:
            raise Denied("topic_peer_mismatch")
        if topic.get("closed") or topic.get("hidden"):
            raise Denied("topic_unavailable")
        if reply_to is not None and reply_to != topic_id:
            # Telethon's high-level reply_to cannot set top_msg_id. Refuse a
            # nested reply rather than risk it falling into General if deleted.
            raise Denied("topic_reply_unsupported")
        return None if topic_id == 1 else topic_id

    async def _messages(self, target, limit, before_id, query=None):
        integer(limit, 1, 50)
        if before_id is not None:
            integer(before_id, 1, 2**31 - 1)
        target = await self._resolve(target, allow_broadcast=True)
        messages = await self.backend.history(target, limit=limit + 1, before_id=before_id, query=query)
        page = messages[:limit]
        records = [self._record(m, target) for m in page]
        payload = {"messages": records, "next_before_id": None, "untrusted_content": True,
                   "order": "message_id_desc"}
        # Cursor is populated after fitting response; preserve room for it.
        while wire_size(payload) > MAX_BYTES - 64 and records:
            records.pop()
        has_more = len(messages) > len(records)
        if has_more and records:
            payload["next_before_id"] = records[-1]["message_id"]
        return payload

    async def get_history(self, peer_id, limit=20, before_id=None):
        return await self._messages(peer_id, limit, before_id)

    async def search_messages(self, peer_id, query, limit=20, before_id=None):
        if not isinstance(query, str) or not query.strip() or len(query) > 256:
            raise Denied("invalid_query")
        return await self._messages(peer_id, limit, before_id, query=query)

    async def read_channel(self, reference, limit=20, before_id=None, text_offset=0):
        """Read one explicitly named public broadcast channel without listing/joining it."""
        if "telegram:read" not in SCOPES.get():
            raise Denied("unauthorized")
        if not self.targeted_channel_reads_enabled:
            raise Denied("channel_reads_disabled")
        integer(limit, 1, 50)
        if before_id is not None:
            integer(before_id, 1, 2**31 - 1)
        integer(text_offset, 0, 2**31 - 1)
        username, post_id = parse_channel_reference(reference)
        if post_id is None and text_offset:
            raise Denied("invalid_argument")
        resolve = getattr(self.backend, "resolve_public_channel", None)
        if resolve is None:
            raise Denied("channel_read_unavailable")
        channel = await resolve(username)
        if not isinstance(channel, dict):
            raise Denied("channel_read_unavailable")
        target = validate_peer_id(channel.get("peer_id"))
        actual_username = channel.get("username")
        title, title_truncated = clip(channel.get("title"), 120)
        if (not isinstance(actual_username, str) or
                actual_username.casefold() != username.casefold()):
            raise Denied("peer_mismatch")

        if post_id is not None:
            if before_id is not None:
                raise Denied("invalid_argument")
            fetch = getattr(self.backend, "message", None)
            if fetch is None:
                raise Denied("channel_read_unavailable")
            message = await fetch(target, post_id)
            if not isinstance(message, dict) or message.get("id") != post_id:
                raise Denied("message_missing")
            payload = {"peer_id": target, "username": actual_username, "title": title,
                       "title_truncated": title_truncated,
                       "messages": [self._record(message, target, exact_text_offset=text_offset)],
                       "next_before_id": None,
                       "complete": True, "incomplete": False, "exact_post": True,
                       "untrusted_content": True, "order": "message_id_desc"}
            return payload

        fetch = getattr(self.backend, "history", None)
        if fetch is None:
            raise Denied("channel_read_unavailable")
        messages = await fetch(target, limit=limit + 1, before_id=before_id, query=None)
        if not isinstance(messages, (list, tuple)):
            raise Denied("channel_read_unavailable")
        messages = list(messages[:limit + 1])
        records = [self._record(message, target) for message in messages]
        has_more = len(records) > limit
        records = records[:limit]
        payload = {"peer_id": target, "username": actual_username, "title": title,
                   "title_truncated": title_truncated, "messages": records,
                   "next_before_id": None, "complete": not has_more, "incomplete": has_more,
                   "exact_post": False, "untrusted_content": True,
                   "order": "message_id_desc"}
        while wire_size(payload) > MAX_BYTES - 64 and records:
            records.pop()
        has_more = len(messages) > len(records)
        payload["incomplete"] = has_more
        payload["complete"] = not has_more
        if has_more and records:
            payload["next_before_id"] = records[-1]["message_id"]
        return payload

    async def list_public_channels(self, limit=20, cursor=None):
        """List only subscribed public broadcast-channel metadata, without posts."""
        if "telegram:read" not in SCOPES.get():
            raise Denied("unauthorized")
        if not self.targeted_channel_reads_enabled:
            raise Denied("channel_reads_disabled")
        integer(limit, 1, 50)
        now = self.clock()
        expired = {key for key, value in self.public_channel_snapshots.items()
                   if value["expires"] <= now}
        for key in expired:
            del self.public_channel_snapshots[key]
        for token, location in list(self.public_channel_cursors.items()):
            if location[0] in expired:
                del self.public_channel_cursors[token]

        if cursor is not None:
            if (not isinstance(cursor, str) or len(cursor) > 128 or
                    cursor not in self.public_channel_cursors):
                raise Denied("invalid_cursor")
            snap, block_index, start = self.public_channel_cursors[cursor]
            if snap not in self.public_channel_snapshots:
                raise Denied("invalid_cursor")
        else:
            snap = next((key for key, value in reversed(self.public_channel_snapshots.items())
                         if value["expires"] > now), None)
            if snap is None:
                start_listing = getattr(self.backend, "start_public_channel_listing", None)
                if start_listing is None:
                    raise Denied("channel_list_unavailable")
                state = start_listing()
                snap = secrets.token_urlsafe(24)
                self.public_channel_snapshots[snap] = {
                    "expires": now + 300, "state": state, "blocks": [], "seen_peer_ids": set()}
                while len(self.public_channel_snapshots) > 4:
                    removed, _ = self.public_channel_snapshots.popitem(last=False)
                    for token, location in list(self.public_channel_cursors.items()):
                        if location[0] == removed:
                            del self.public_channel_cursors[token]
            block_index, start = 0, 0

        listing = self.public_channel_snapshots[snap]
        self.public_channel_snapshots.move_to_end(snap)
        if block_index == len(listing["blocks"]):
            fetch = getattr(self.backend, "public_channel_page", None)
            if fetch is None:
                raise Denied("channel_list_unavailable")
            result = await fetch(listing["state"], limit)
            if (not isinstance(result, dict) or not isinstance(result.get("rows"), (list, tuple)) or
                    type(result.get("done")) is not bool or type(result.get("truncated")) is not bool):
                raise Denied("channel_list_unavailable")
            channels = []
            seen_peer_ids = set(listing["seen_peer_ids"])
            for row in result["rows"]:
                if not isinstance(row, dict) or row.get("type") != "broadcast_channel":
                    continue
                username = row.get("username")
                if not isinstance(username, str) or not CHANNEL_USERNAME.fullmatch(username):
                    continue
                try:
                    target = validate_peer_id(row.get("peer_id"))
                except Denied:
                    raise Denied("channel_list_unavailable") from None
                if target > -1_000_000_000_000:
                    raise Denied("channel_list_unavailable")
                if target in seen_peer_ids:
                    continue
                seen_peer_ids.add(target)
                raw_title = row.get("title")
                raw_title = raw_title if isinstance(raw_title, str) else ""
                safe_title = "".join(ch for ch in raw_title if ord(ch) >= 0x20 and ord(ch) != 0x7f)
                title, title_truncated = clip(safe_title, 120)
                channels.append({"peer_id": target, "username": username, "title": title,
                                 "title_truncated": title_truncated,
                                 "public_url": f"https://t.me/{username}"})
            listing["seen_peer_ids"] = seen_peer_ids
            listing["blocks"].append({"rows": channels, "done": result["done"],
                                      "truncated": result["truncated"]})

        block = listing["blocks"][block_index]
        page = block["rows"][start:start + limit]
        payload = {"channels": page, "next_cursor": None, "complete": False,
                   "incomplete": True, "truncated": block["truncated"],
                   "untrusted_content": True}
        # Keep room for the random cursor in the bounded MCP response.
        if start + len(page) < len(block["rows"]) or (not block["done"] and not block["truncated"]):
            payload["next_cursor"] = "x" * 32
        while wire_size(payload) > MAX_BYTES - 64 and page:
            page.pop()
        next_location = None
        end = start + len(page)
        if end < len(block["rows"]):
            next_location = (snap, block_index, end)
        elif not block["done"] and not block["truncated"]:
            next_location = (snap, block_index + 1, 0)
        if next_location is not None:
            token = secrets.token_urlsafe(24)
            self.public_channel_cursors[token] = next_location
            while len(self.public_channel_cursors) > 256:
                self.public_channel_cursors.popitem(last=False)
            payload["next_cursor"] = token
        else:
            payload["next_cursor"] = None
        complete = next_location is None and block["done"] and not block["truncated"]
        payload["complete"] = complete
        payload["incomplete"] = not complete
        return payload

    async def get_reply_context(self, peer_id, message_id, radius=3):
        integer(message_id, 1, 2**31 - 1)
        integer(radius, 0, 10)
        target = await self._resolve(peer_id, allow_broadcast=True)
        message = await self.backend.message(target, message_id)
        if message is None:
            return {"error": "message_missing"}
        topic = None
        topic_candidate = message.get("topic_id") or message.get("reply_to")
        if (type(topic_candidate) is int and 1 <= topic_candidate <= 2**31 - 1 and
                message.get("reply_peer_id") in {None, target} and
                getattr(self.backend, "is_forum_group", lambda _target: False)(target)):
            found = await self.backend.forum_topic(target, topic_candidate)
            if (found is not None and not found["deleted"] and found["peer_id"] == target
                    and found["topic_id"] == topic_candidate):
                topic = dict(found)
                topic["title"], topic["title_truncated"] = clip(topic["title"])
        before, after = await self.backend.around(target, message_id, radius)
        records = [self._record(m, target) for m in sorted([*before, message, *after], key=lambda m: m["id"])]
        reply = None
        reply_state = "none"
        if message.get("reply_to"):
            reply_peer = message.get("reply_peer_id")
            if reply_peer is not None and reply_peer != target:
                reply_state = "cross_peer_reference_only"
            else:
                replied = await self.backend.message(target, message["reply_to"])
                reply = self._record(replied, target) if replied else None
                reply_state = "available" if replied else "missing"
        payload = {"target_message_id": message_id, "messages": records, "replied_message": reply,
                   "forum_topic": topic,
                   "reply_state": reply_state, "context_truncated": False, "untrusted_content": True}
        # Keep target and quote; trim outer context until bounded.
        while wire_size(payload) > MAX_BYTES and len(records) > 1:
            index = max((i for i, r in enumerate(records) if r["message_id"] != message_id),
                        key=lambda i: abs(records[i]["message_id"] - message_id))
            records.pop(index)
            payload["context_truncated"] = True
        return payload

    async def send_message(self, peer_id, text, reply_to=None, first_contact_message_id=None,
                           topic_id=None):
        target = validate_peer_id(peer_id)
        if topic_id is not None:
            integer(topic_id, 1, 2**31 - 1)
        if reply_to is not None:
            integer(reply_to, 1, 2**31 - 1)
        if first_contact_message_id is not None:
            integer(first_contact_message_id, 1, 2**31 - 1)
        # A broad selector is only a candidate until peer class is resolved.
        # Explicit denies and default-deny still stop before contacting Telegram.
        candidates = self.policy.precheck(target, text, SCOPES.get(), self.clock())
        first_rules = tuple(g for g in candidates if g.first_contact)
        if first_contact_message_id is None:
            if first_rules and not any(not g.first_contact for g in candidates):
                raise Denied("first_contact_message_required")
        elif not first_rules or reply_to != first_contact_message_id:
            raise Denied("invalid_first_contact_reference")
        if self.quotas is None:
            raise Denied("send_quota_unavailable")
        target, peer_type = await self._resolve(target, return_type=True)
        send_reply_to = await self._topic_address(target, peer_type, topic_id, reply_to)
        needs_human = peer_type == "user" or any(
            g.selector in {"all_human_dms", "first_contact"} for g in candidates)
        is_human = False
        if needs_human:
            check_human = getattr(self.backend, "is_human_user", None)
            is_human = bool(check_human and await check_human(target))
            if not is_human:
                raise Denied("peer_not_human")
        first_contact_verified = False
        if first_rules and first_contact_message_id is not None:
            verify = getattr(self.backend, "verify_first_inbound", None)
            try:
                first_contact_verified = bool(verify and await verify(target, first_contact_message_id))
            except Exception as exc:
                if type(exc).__name__ in {"FloodWaitError", "SlowModeWaitError", "FloodPremiumWaitError"}:
                    raise
                raise Denied("first_contact_unavailable") from None
            if not first_contact_verified:
                raise Denied("first_contact_unverified")
        if reply_to is not None and topic_id is None and not first_contact_verified and await self.backend.message(target, reply_to) is None:
            raise Denied("reply_target_missing")
        # Recheck expiry after async resolution and reserve transactionally.
        grant = self.policy.authorize(target, text, SCOPES.get(), self.clock(),
                                      peer_type=peer_type, is_human=is_human,
                                      first_contact_verified=first_contact_verified)
        try:
            self.quotas.reserve(grant, self.clock(),
                                first_contact_message_id=first_contact_message_id if grant.first_contact else None)
        except Denied:
            raise
        except Exception:
            raise Denied("send_quota_unavailable") from None
        try:
            self._send_attempted = True
            result = await self.backend.send(target, text, send_reply_to)
        except BaseException:
            if grant.first_contact and first_contact_message_id is not None:
                self.quotas.finish_first_contact(target, first_contact_message_id, "unknown")
            raise
        if type(result) is not int or result <= 0:
            if grant.first_contact and first_contact_message_id is not None:
                self.quotas.finish_first_contact(target, first_contact_message_id, "unknown")
            raise Denied("delivery_unknown")
        if grant.first_contact and first_contact_message_id is not None:
            self.quotas.finish_first_contact(target, first_contact_message_id, "sent")
        payload = {"sent": True, "peer_id": target, "message_id": result}
        if topic_id is not None:
            payload["topic_id"] = topic_id
        return payload

    async def send_media(self, peer_id, items, reply_to=None, topic_id=None):
        target = validate_peer_id(peer_id)
        if topic_id is not None:
            integer(topic_id, 1, 2**31 - 1)
        if reply_to is not None:
            integer(reply_to, 1, 2**31 - 1)
        if not isinstance(items, list) or not 1 <= len(items) <= MAX_OUTBOUND_ITEMS:
            raise Denied("invalid_media_count")
        normalized = []
        for item in items:
            if hasattr(item, "model_dump"):
                item = item.model_dump()
            if not isinstance(item, dict):
                raise Denied("invalid_media")
            normalized.append(item)
        kinds = [item.get("media_type") for item in normalized]
        if len(items) > 1 and any(kind not in {"photo", "video"} for kind in kinds):
            raise Denied("invalid_media_album")
        captions = [item.get("caption") for item in normalized]
        candidates = self.policy.precheck_media(target, captions, SCOPES.get(), self.clock())
        if self.quotas is None:
            raise Denied("send_quota_unavailable")

        total_bytes = 0
        with temporary_media_dir() as directory:
            files = []
            for index, item in enumerate(normalized):
                item_directory = Path(directory) / str(index)
                item_directory.mkdir(mode=0o700)
                prepared = await prepare_outbound_media(
                    item, item_directory, remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES - total_bytes)
                total_bytes += prepared.path.stat().st_size
                if total_bytes > MAX_OUTBOUND_MEDIA_BYTES:
                    raise Denied("media_too_large")
                files.append(prepared)

            target, peer_type = await self._resolve(target, return_type=True)
            send_reply_to = await self._topic_address(target, peer_type, topic_id, reply_to)
            needs_human = peer_type == "user" or any(
                grant.selector in {"all_human_dms", "first_contact"} for grant in candidates)
            is_human = False
            if needs_human:
                check_human = getattr(self.backend, "is_human_user", None)
                is_human = bool(check_human and await check_human(target))
                if not is_human:
                    raise Denied("peer_not_human")
            grant = self.policy.authorize_media(target, captions, SCOPES.get(), self.clock(),
                                                peer_type=peer_type, is_human=is_human)
            if reply_to is not None and topic_id is None and await self.backend.message(target, reply_to) is None:
                raise Denied("reply_target_missing")
            send = getattr(self.backend, "send_media_files", None)
            if send is None:
                raise Denied("media_send_unavailable")
            try:
                self.quotas.reserve(grant, self.clock(), count=len(files))
            except Denied:
                raise
            except Exception:
                raise Denied("send_quota_unavailable") from None
            try:
                self._send_attempted = True
                message_ids = await send(target, files, send_reply_to)
            except BaseException:
                # Telegram may have accepted all or part of an album before a
                # transport failure. Never retry an uncertain media send.
                raise
        if (not isinstance(message_ids, list) or len(message_ids) != len(files) or
                any(type(value) is not int or value <= 0 for value in message_ids)):
            raise Denied("delivery_unknown")
        payload = {"sent": True, "peer_id": target, "message_ids": message_ids,
                   "media_count": len(files), "album": len(files) > 1}
        if topic_id is not None:
            payload["topic_id"] = topic_id
        return payload
