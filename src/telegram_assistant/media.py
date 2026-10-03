"""Bounded, opt-in media helpers. No speech or vision model runs locally."""
from __future__ import annotations

import asyncio
import base64
import binascii
import codecs
import json
import math
import mimetypes
import os
import re
import shutil
import tempfile
import time
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from .security import Denied

MAX_IMAGE_INPUT_BYTES = 8 * 1024 * 1024
MAX_IMAGE_PIXELS = 12_000_000
MAX_IMAGE_PREVIEW_EDGE = 1280
MAX_IMAGE_PREVIEW_BYTES = 256 * 1024
MAX_AUDIO_INPUT_BYTES = 20 * 1024 * 1024
MAX_AUDIO_SECONDS = 300
MAX_OUTBOUND_MEDIA_BYTES = 20 * 1024 * 1024
MAX_OUTBOUND_PHOTO_BYTES = 8 * 1024 * 1024
MAX_OUTBOUND_STICKER_BYTES = 512 * 1024
MAX_OUTBOUND_ITEMS = 10
MAX_OUTBOUND_CAPTION_UNITS = 1024
MAX_OUTBOUND_MEDIA_SECONDS = 300
MAX_MEDIA_RESPONSE_BYTES = 512 * 1024
MAX_TRANSCRIPTION_RESPONSE_BYTES = 64 * 1024
MAX_TRANSCRIPT_CHARS = 12_000
MEDIA_TIMEOUT_SECONDS = 90
MEDIA_CACHE_TTL_SECONDS = 300
MEDIA_CACHE_MAX_BYTES = 3 * 1024 * 1024
_CHUNK_BYTES = 64 * 1024
_OPENAI_TRANSCRIPTIONS_URL = "https://api.openai.com/v1/audio/transcriptions"
_OPENAI_MODEL = "gpt-4o-mini-transcribe"


@dataclass(frozen=True)
class ImageResult:
    data: bytes
    mime_type: str = "image/jpeg"


@dataclass(frozen=True)
class OutboundMediaFile:
    path: Path
    media_type: str
    mime_type: str
    filename: str
    caption: str | None
    sticker_emoji: str | None = None
    duration: float | None = None
    width: int | None = None
    height: int | None = None
    voice: bool = False
    has_audio: bool = False


def _utf16_units(value: str) -> int:
    try:
        return len(value.encode("utf-16-le")) // 2
    except UnicodeError:
        raise Denied("invalid_media_caption") from None


def _safe_outbound_filename(value, extension: str) -> str:
    if value is None:
        value = "attachment"
    if (not isinstance(value, str) or not value or len(value) > 255 or
            "/" in value or "\\" in value or any(ord(char) < 32 for char in value)):
        raise Denied("invalid_media_filename")
    normalized = unicodedata.normalize("NFKC", value)
    suffix = Path(normalized).suffix
    stem = normalized[:-len(suffix)] if suffix else normalized
    stem = re.sub(r"[^\w .()\-]", "_", stem, flags=re.UNICODE).strip(" .")[:100]
    if not stem or stem in {".", ".."}:
        raise Denied("invalid_media_filename")
    return f"{stem}{extension}"


def _write_private_file(directory: Path, filename: str, data: bytes) -> Path:
    path = directory / filename
    try:
        with path.open("xb") as output:
            os.fchmod(output.fileno(), 0o600)
            output.write(data)
    except OSError:
        raise Denied("media_tempfile_unavailable") from None
    return path


def _probe_media_streams(info: dict, *, require_video: bool, allow_audio: bool) -> tuple[dict, float]:
    streams = info.get("streams")
    if not isinstance(streams, list) or not streams:
        raise Denied("invalid_media")
    videos = [s for s in streams if isinstance(s, dict) and s.get("codec_type") == "video"]
    audios = [s for s in streams if isinstance(s, dict) and s.get("codec_type") == "audio"]
    if (len(videos) != (1 if require_video else 0) or len(audios) > (1 if allow_audio else 0) or
            len(videos) + len(audios) != len(streams)):
        raise Denied("unsupported_media_format")
    duration = _duration(info)
    if duration > MAX_OUTBOUND_MEDIA_SECONDS:
        raise Denied("media_too_long")
    stream = videos[0] if videos else audios[0]
    width, height = stream.get("width"), stream.get("height")
    if require_video:
        if (type(width) is not int or type(height) is not int or width <= 0 or height <= 0 or
                width * height > MAX_IMAGE_PIXELS):
            raise Denied("image_too_many_pixels")
    return stream, duration


async def prepare_outbound_media(item, directory: Path, *, remaining_bytes: int) -> OutboundMediaFile:
    """Decode one MCP base64 attachment to an owner-only temp file and verify its bytes."""
    if not isinstance(item, dict):
        raise Denied("invalid_media")
    media_type = item.get("media_type")
    if not isinstance(media_type, str) or media_type not in {
            "photo", "video", "document", "audio", "voice", "animation", "sticker"}:
        raise Denied("unsupported_media_type")
    encoded = item.get("data_base64")
    if type(encoded) is not str or not encoded or len(encoded) > ((min(remaining_bytes, MAX_OUTBOUND_MEDIA_BYTES) + 2) // 3) * 4:
        raise Denied("media_too_large" if type(encoded) is str else "invalid_media")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise Denied("invalid_media_base64") from None
    if not raw or len(raw) > remaining_bytes or len(raw) > MAX_OUTBOUND_MEDIA_BYTES:
        raise Denied("media_too_large")
    caption = item.get("caption")
    if caption is not None and (not isinstance(caption, str) or _utf16_units(caption) > MAX_OUTBOUND_CAPTION_UNITS):
        raise Denied("invalid_media_caption")
    supplied_name = item.get("filename")
    if supplied_name is not None and (not isinstance(supplied_name, str) or not supplied_name or
                                      len(supplied_name) > 255 or "/" in supplied_name or
                                      "\\" in supplied_name or any(ord(char) < 32 for char in supplied_name)):
        raise Denied("invalid_media_filename")
    emoji = item.get("sticker_emoji")
    if media_type == "sticker":
        if (not isinstance(emoji, str) or not 1 <= len(emoji) <= 8 or
                any(ord(char) < 32 for char in emoji) or
                not any(unicodedata.category(char) in {"So", "Sk"} for char in emoji) or
                caption is not None):
            raise Denied("invalid_sticker")
        if len(raw) > MAX_OUTBOUND_STICKER_BYTES:
            raise Denied("media_too_large")
        if sniff_image_mime_path_bytes(raw) != "image/webp":
            raise Denied("unsupported_sticker_format")
        if _webp_is_animated(raw):
            raise Denied("animated_stickers_unsupported")
        ext, mime_type = ".webp", "image/webp"
    elif emoji is not None:
        raise Denied("invalid_sticker")
    elif media_type == "photo":
        if len(raw) > MAX_OUTBOUND_PHOTO_BYTES:
            raise Denied("media_too_large")
        mime_type = sniff_image_mime_path_bytes(raw)
        # Telethon's pinned MTProto client uploads only JPEG/PNG as photos;
        # a static WebP file is supported separately as a sticker or document.
        if mime_type not in {"image/jpeg", "image/png"}:
            raise Denied("unsupported_image_format")
        ext = {"image/jpeg": ".jpg", "image/png": ".png", "image/webp": ".webp"}[mime_type]
    elif media_type == "animation":
        if sniff_image_mime_path_bytes(raw) != "image/gif":
            raise Denied("unsupported_animation_format")
        ext, mime_type = ".gif", "image/gif"
    elif media_type == "video":
        if len(raw) > MAX_OUTBOUND_MEDIA_BYTES:
            raise Denied("media_too_large")
        ext, mime_type = (".mp4", "video/mp4") if len(raw) >= 12 and raw[4:8] == b"ftyp" else (".webm", "video/webm")
        if mime_type == "video/webm" and not _is_webm(raw[:4096]):
            raise Denied("unsupported_video_format")
    elif media_type in {"audio", "voice"}:
        if len(raw) > MAX_AUDIO_INPUT_BYTES:
            raise Denied("media_too_large")
        kind = sniff_audio_kind_bytes(raw)
        if media_type == "voice" and kind != "ogg-opus":
            raise Denied("unsupported_voice_format")
        ext, mime_type = {
            "ogg-opus": (".ogg", "audio/ogg"), "mp3": (".mp3", "audio/mpeg"),
            "mp4": (".m4a", "audio/mp4"), "wav": (".wav", "audio/wav"),
            "webm": (".webm", "audio/webm"),
        }[kind]
    else:
        mime_type = _document_mime_from_bytes(raw)
        filename = _document_filename_from_bytes(raw, item.get("filename"), mime_type)
        path = _write_private_file(directory, filename, raw)
        return OutboundMediaFile(path, media_type, mime_type, filename, caption)

    filename = _safe_outbound_filename(item.get("filename"), ext)
    path = _write_private_file(directory, filename, raw)
    duration = width = height = None
    has_audio = False
    if media_type in {"photo", "sticker"}:
        info = await _probe(path, image=True)
        streams = info.get("streams")
        if (not isinstance(streams, list) or len(streams) != 1 or
                not isinstance(streams[0], dict) or streams[0].get("codec_type") != "video"):
            raise Denied("invalid_media")
        stream = streams[0]
        width, height = stream.get("width"), stream.get("height")
        if (type(width) is not int or type(height) is not int or width <= 0 or height <= 0 or
                width * height > MAX_IMAGE_PIXELS):
            raise Denied("image_too_many_pixels")
        if media_type == "sticker" and (width > 512 or height > 512):
            raise Denied("sticker_dimensions_exceeded")
    elif media_type in {"video", "animation"}:
        info = await _probe(path, image=True)
        stream, duration = _probe_media_streams(info,
            require_video=True,
            allow_audio=media_type == "video")
        width, height = stream.get("width"), stream.get("height")
        has_audio = any(isinstance(stream, dict) and stream.get("codec_type") == "audio"
                        for stream in info.get("streams", []))
    elif media_type in {"audio", "voice"}:
        kind = sniff_audio_kind(path)
        duration, _, _ = await _verified_audio(path, kind, MAX_AUDIO_SECONDS)
    return OutboundMediaFile(path, media_type, mime_type, filename, caption,
                             sticker_emoji=emoji, duration=duration,
                             width=width, height=height, voice=media_type == "voice",
                             has_audio=has_audio)


def sniff_image_mime_path_bytes(data: bytes) -> str:
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    raise Denied("unsupported_image_format")


def sniff_audio_kind_bytes(data: bytes) -> str:
    head = data[:4096]
    if head.startswith(b"OggS"):
        if b"OpusHead" not in head:
            raise Denied("unsupported_audio_format")
        return "ogg-opus"
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return "wav"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "mp4"
    if _is_webm(head):
        return "webm"
    if head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0):
        return "mp3"
    raise Denied("unsupported_audio_format")


def _webp_is_animated(data: bytes) -> bool:
    if len(data) < 12 or data[:4] != b"RIFF" or data[8:12] != b"WEBP":
        return False
    cursor = 12
    while cursor + 8 <= len(data):
        tag = data[cursor:cursor + 4]
        size = int.from_bytes(data[cursor + 4:cursor + 8], "little")
        end = cursor + 8 + size
        if end > len(data):
            raise Denied("invalid_media")
        if tag in {b"ANIM", b"ANMF"}:
            return True
        if tag == b"VP8X" and size and data[cursor + 8] & 0x02:
            return True
        cursor = end + (size & 1)
    return False


def _document_mime_from_bytes(data: bytes) -> str:
    head = data[:4096]
    if head.startswith(b"%PDF-"):
        return "application/pdf"
    if head.startswith(b"{\\rtf"):
        return "application/rtf"
    if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "application/x-ole-storage"
    if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return "application/zip"
    if head.startswith(b"\x1f\x8b"):
        return "application/gzip"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "application/x-tar"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if head.startswith(b"OggS"):
        return "application/ogg"
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return "audio/wav"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "video/mp4"
    if _is_webm(head):
        return "video/webm"
    if head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0):
        return "audio/mpeg"
    try:
        if b"\x00" in data:
            return "application/octet-stream"
        decoder = codecs.getincrementaldecoder("utf-8")("strict")
        for offset in range(0, len(data), _CHUNK_BYTES):
            decoder.decode(data[offset:offset + _CHUNK_BYTES])
        decoder.decode(b"", final=True)
        if b"\x00" in head:
            return "application/octet-stream"
        return "text/plain"
    except UnicodeError:
        return "application/octet-stream"


def _document_filename_from_bytes(data: bytes, supplied: str | None, mime_type: str) -> str:
    extension = Path(supplied).suffix.lower() if supplied else ""
    expected = mimetypes.guess_type("file" + extension, strict=False)[0] if extension else None
    accepted = {
        "application/zip": {"application/zip", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                             "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                             "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                             "application/epub+zip", "application/vnd.oasis.opendocument.text",
                             "application/vnd.oasis.opendocument.spreadsheet"},
        "text/plain": {"text/plain", "text/csv", "text/markdown", "application/json", "application/xml",
                       "text/xml", "text/html", "text/tab-separated-values", "message/rfc822"},
        "application/x-ole-storage": {"application/x-ole-storage", "application/msword",
                                       "application/vnd.ms-excel", "application/vnd.ms-powerpoint"},
        "application/ogg": {"application/ogg", "audio/ogg", "audio/opus"},
        "audio/wav": {"audio/wav", "audio/x-wav", "audio/wave"},
        "audio/mpeg": {"audio/mpeg", "audio/mp3", "audio/x-mp3"},
        "video/mp4": {"video/mp4", "audio/mp4", "audio/x-m4v"},
    }
    if (mime_type != "application/octet-stream" and expected and expected != mime_type and
            expected not in accepted.get(mime_type, set())):
        raise Denied("media_mime_mismatch")
    suffix = extension or ".bin"
    return _safe_outbound_filename(supplied, suffix)


@dataclass(frozen=True)
class TranscriptionConfig:
    provider: str = "off"
    key: str | None = field(default=None, repr=False)
    monthly_seconds: int = 0
    max_duration_seconds: int = MAX_AUDIO_SECONDS

    def __post_init__(self):
        if self.provider not in {"off", "openai"}:
            raise Denied("invalid_transcription_config")
        if type(self.monthly_seconds) is not int or not 0 <= self.monthly_seconds <= 31 * 24 * 3600:
            raise Denied("invalid_transcription_config")
        if (type(self.max_duration_seconds) is not int or
                not 1 <= self.max_duration_seconds <= MAX_AUDIO_SECONDS):
            raise Denied("invalid_transcription_config")
        if self.provider == "openai":
            if (not isinstance(self.key, str) or not 20 <= len(self.key) <= 4096 or
                    not all(0x21 <= ord(char) <= 0x7E for char in self.key)):
                raise Denied("invalid_transcription_config")
        elif self.key is not None:
            raise Denied("invalid_transcription_config")


class MediaCache:
    """Short-lived, byte-bounded cache of rendered previews and transcripts."""
    def __init__(self, *, clock=time.monotonic, ttl=MEDIA_CACHE_TTL_SECONDS,
                 max_bytes=MEDIA_CACHE_MAX_BYTES):
        self.clock, self.ttl, self.max_bytes = clock, ttl, max_bytes
        self.items = OrderedDict()
        self.byte_count = 0

    @staticmethod
    def _size(value):
        if isinstance(value, ImageResult):
            return len(value.data)
        if isinstance(value, str):
            return len(value.encode("utf-8"))
        if isinstance(value, tuple) and len(value) == 2 and isinstance(value[0], str):
            return len(value[0].encode("utf-8"))
        return 0

    def get(self, key):
        now = self.clock()
        for old_key, (expires, value, size) in list(self.items.items()):
            if expires <= now:
                self.items.pop(old_key, None)
                self.byte_count -= size
        item = self.items.get(key)
        if item is None:
            return None
        self.items.move_to_end(key)
        return item[1]

    def put(self, key, value):
        size = self._size(value)
        if not size or size > self.max_bytes:
            return
        old = self.items.pop(key, None)
        if old is not None:
            self.byte_count -= old[2]
        while self.items and self.byte_count + size > self.max_bytes:
            _, (_, _, removed_size) = self.items.popitem(last=False)
            self.byte_count -= removed_size
        self.items[key] = (self.clock() + self.ttl, value, size)
        self.byte_count += size


def _read_prefix(path: Path, size=4096) -> bytes:
    try:
        with path.open("rb") as stream:
            return stream.read(size)
    except OSError:
        raise Denied("media_unavailable") from None


def sniff_image_mime(path: Path) -> str:
    head = _read_prefix(path, 16)
    if head.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if len(head) >= 12 and head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image/webp"
    raise Denied("unsupported_image_format")


def _ebml_vint(data: bytes, offset: int, *, keep_marker: bool) -> tuple[int, int]:
    if offset >= len(data) or data[offset] == 0:
        raise ValueError
    first = data[offset]
    mask, width = 0x80, 1
    while not first & mask and width <= 8:
        mask >>= 1
        width += 1
    if width > 8 or offset + width > len(data):
        raise ValueError
    value = first if keep_marker else first & (mask - 1)
    for byte in data[offset + 1:offset + width]:
        value = (value << 8) | byte
    return value, offset + width


def _is_webm(head: bytes) -> bool:
    """Distinguish a WebM EBML header from a generic Matroska document."""
    if not head.startswith(b"\x1a\x45\xdf\xa3"):
        return False
    try:
        header_size, cursor = _ebml_vint(head, 4, keep_marker=False)
        end = min(len(head), cursor + header_size)
        while cursor < end:
            element_id, cursor = _ebml_vint(head, cursor, keep_marker=True)
            element_size, cursor = _ebml_vint(head, cursor, keep_marker=False)
            next_cursor = cursor + element_size
            if next_cursor > end:
                return False
            if element_id == 0x4282:
                return head[cursor:next_cursor] == b"webm"
            cursor = next_cursor
    except ValueError:
        return False
    return False


def sniff_audio_kind(path: Path) -> str:
    head = _read_prefix(path, 4096)
    if head.startswith(b"OggS"):
        # Telethon voice notes are Opus in Ogg. Other Ogg codecs are not
        # advertised by the selected provider and are rejected before upload.
        if b"OpusHead" not in head:
            raise Denied("unsupported_audio_format")
        return "ogg-opus"
    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return "wav"
    if len(head) >= 12 and head[4:8] == b"ftyp":
        return "mp4"
    if _is_webm(head):
        return "webm"
    # MP3 frames often start immediately; ID3 is the optional tag header.
    if head.startswith(b"ID3") or (len(head) >= 2 and head[0] == 0xFF and head[1] & 0xE0 == 0xE0):
        return "mp3"
    raise Denied("unsupported_audio_format")


def _ffmpeg_binary() -> str:
    binary = shutil.which("ffmpeg")
    if not binary:
        raise Denied("media_processor_unavailable")
    return binary


def _ffprobe_binary() -> str:
    binary = shutil.which("ffprobe")
    if not binary:
        raise Denied("media_processor_unavailable")
    return binary


async def _run_bounded(argv, *, timeout=15, max_stdout=MAX_TRANSCRIPTION_RESPONSE_BYTES):
    try:
        process = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except (OSError, ValueError):
        raise Denied("media_processor_unavailable") from None

    async def read_output():
        output = bytearray()
        while True:
            chunk = await process.stdout.read(min(_CHUNK_BYTES, max_stdout + 1 - len(output)))
            if not chunk:
                return bytes(output)
            if len(output) + len(chunk) > max_stdout:
                process.kill()
                raise Denied("media_processing_overflow")
            output.extend(chunk)

    async def collect():
        output = await read_output()
        return output, await process.wait()

    try:
        stdout, returncode = await asyncio.wait_for(collect(), timeout=timeout)
    except TimeoutError:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise Denied("media_processing_timeout") from None
    except asyncio.CancelledError:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    except Denied:
        if process.returncode is None:
            process.kill()
        await process.wait()
        raise
    if returncode != 0:
        raise Denied("invalid_media")
    return stdout


async def _probe(path: Path, *, image=False) -> dict:
    argv = [_ffprobe_binary(), "-v", "error"]
    if image:
        argv.extend(["-max_pixels", str(MAX_IMAGE_PIXELS)])
    argv.extend(["-protocol_whitelist", "file,pipe", "-show_entries",
        "format=format_name,duration:stream=codec_type,codec_name,width,height,duration",
        "-of", "json", str(path)])
    raw = await _run_bounded(argv, timeout=12, max_stdout=16 * 1024)
    try:
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (ValueError, UnicodeError):
        raise Denied("invalid_media") from None


def _duration(info: dict) -> float:
    formats = info.get("format")
    raw = formats.get("duration") if isinstance(formats, dict) else None
    try:
        duration = float(raw)
    except (TypeError, ValueError):
        raise Denied("audio_duration_unavailable") from None
    if not math.isfinite(duration) or duration <= 0:
        raise Denied("audio_duration_unavailable")
    return duration


async def _verified_audio(path: Path, kind: str, max_seconds: int) -> tuple[float, str, str]:
    info = await _probe(path)
    streams = info.get("streams")
    if (not isinstance(streams, list) or
            not any(isinstance(stream, dict) and stream.get("codec_type") == "audio"
                    for stream in streams) or
            any(isinstance(stream, dict) and stream.get("codec_type") not in {"audio", "attachment"}
                for stream in streams)):
        raise Denied("unsupported_audio_format")
    audio_stream = next(stream for stream in streams
                        if isinstance(stream, dict) and stream.get("codec_type") == "audio")
    codec = audio_stream.get("codec_name")
    formats = info.get("format")
    format_names = set(formats.get("format_name", "").split(",")) if isinstance(formats, dict) else set()
    valid_container = {
        "ogg-opus": "ogg" in format_names and codec == "opus",
        "webm-opus": "webm" in format_names and codec == "opus",
        "mp3": "mp3" in format_names and codec == "mp3",
        "mp4": bool(format_names & {"mp4", "m4a"}),
        "wav": "wav" in format_names,
        "webm": "webm" in format_names,
    }.get(kind, False)
    if not valid_container:
        raise Denied("unsupported_audio_format")
    duration = _duration(info)
    if duration > max_seconds:
        raise Denied("audio_too_long")
    name, mime = {
        "ogg-opus": ("telegram-audio.webm", "audio/webm"),
        "webm-opus": ("telegram-audio.webm", "audio/webm"),
        "mp3": ("telegram-audio.mp3", "audio/mpeg"),
        "mp4": ("telegram-audio.m4a", "audio/mp4"),
        "wav": ("telegram-audio.wav", "audio/wav"),
        "webm": ("telegram-audio.webm", "audio/webm"),
    }[kind]
    return duration, name, mime


async def prepare_audio(path: Path, workdir: Path, *, max_seconds=MAX_AUDIO_SECONDS) -> tuple[Path, str, str, float]:
    """Validate actual container/codec and remux Telegram Ogg/Opus to WebM."""
    size = path.stat().st_size
    if size <= 0 or size > MAX_AUDIO_INPUT_BYTES:
        raise Denied("audio_too_large")
    kind = sniff_audio_kind(path)
    duration, name, mime = await _verified_audio(path, kind, max_seconds)
    if kind != "ogg-opus":
        return path, name, mime, duration
    output = workdir / "telegram-audio.webm"
    await _run_bounded([
        _ffmpeg_binary(), "-nostdin", "-v", "error", "-y", "-protocol_whitelist",
        "file,pipe", "-i", str(path),
        "-map", "0:a:0", "-vn", "-c:a", "copy", "-f", "webm", str(output)],
        timeout=20, max_stdout=1024)
    out_size = output.stat().st_size
    if out_size <= 0 or out_size > MAX_AUDIO_INPUT_BYTES:
        raise Denied("audio_too_large")
    remux_duration, name, mime = await _verified_audio(output, "webm-opus", max_seconds)
    return output, name, mime, remux_duration


async def preview_image(path: Path) -> ImageResult:
    size = path.stat().st_size
    if size <= 0 or size > MAX_IMAGE_INPUT_BYTES:
        raise Denied("image_too_large")
    sniff_image_mime(path)
    info = await _probe(path, image=True)
    streams = info.get("streams")
    video = next((stream for stream in streams or () if isinstance(stream, dict) and
                  stream.get("codec_type") == "video"), None)
    if video is None:
        raise Denied("invalid_image")
    width, height = video.get("width"), video.get("height")
    if type(width) is not int or type(height) is not int or width < 1 or height < 1:
        raise Denied("invalid_image")
    if width * height > MAX_IMAGE_PIXELS:
        raise Denied("image_too_many_pixels")
    ffmpeg = _ffmpeg_binary()
    # Reduce detail progressively until the serialized MCP image stays within
    # its independent preview budget. Each pass is bounded and runs locally.
    for edge in (MAX_IMAGE_PREVIEW_EDGE, 1024, 768, 512, 256):
        try:
            preview = await _run_bounded([
                ffmpeg, "-nostdin", "-v", "error", "-threads", "1", "-max_pixels",
                str(MAX_IMAGE_PIXELS), "-protocol_whitelist", "file,pipe", "-i", str(path), "-frames:v", "1", "-vf",
                f"scale=w='min({edge},iw)':h='min({edge},ih)':force_original_aspect_ratio=decrease:force_divisible_by=2",
                "-q:v", "9", "-f", "image2pipe", "-vcodec", "mjpeg", "pipe:1"],
                timeout=10, max_stdout=MAX_IMAGE_PREVIEW_BYTES * 2)
        except Denied as exc:
            if exc.code == "media_processing_overflow":
                continue
            raise
        if preview and preview.startswith(b"\xff\xd8\xff") and len(preview) <= MAX_IMAGE_PREVIEW_BYTES:
            return ImageResult(preview)
    raise Denied("image_preview_too_large")


def temporary_media_dir() -> tempfile.TemporaryDirectory:
    """A private per-call directory; caller must use it as a context manager."""
    return tempfile.TemporaryDirectory(prefix="telegram-assistant-media-")


class OpenAITranscriber:
    """One provider adapter with no redirects, retries, or unbounded response body."""
    def __init__(self, api_key: str, *, http=None):
        self.api_key = api_key
        if http is None:
            import httpx
            http = httpx.AsyncClient(
                timeout=httpx.Timeout(connect=5, read=45, write=25, pool=5),
                limits=httpx.Limits(max_connections=2, max_keepalive_connections=1),
                follow_redirects=False, trust_env=False)
        self.http = http

    async def transcribe(self, path: Path, *, filename: str, mime_type: str) -> str:
        try:
            import httpx
            with path.open("rb") as stream:
                async with self.http.stream(
                        "POST", _OPENAI_TRANSCRIPTIONS_URL,
                        headers={"Authorization": f"Bearer {self.api_key}"},
                        data={"model": _OPENAI_MODEL, "response_format": "json"},
                        files={"file": (filename, stream, mime_type)}) as response:
                    chunks, size = [], 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > MAX_TRANSCRIPTION_RESPONSE_BYTES:
                            raise Denied("transcription_response_too_large")
                        chunks.append(chunk)
                    if response.status_code != 200:
                        raise Denied("transcription_provider_error")
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    if content_type != "application/json":
                        raise Denied("transcription_provider_error")
            payload = json.loads(b"".join(chunks))
            text = payload.get("text") if isinstance(payload, dict) else None
            if not isinstance(text, str):
                raise Denied("transcription_provider_error")
            return text
        except Denied:
            raise
        except (OSError, ValueError, UnicodeError, TypeError):
            raise Denied("transcription_provider_error") from None
        except Exception:
            # Provider error bodies and exception messages may contain payloads
            # or credentials; the service returns only this fixed code.
            raise Denied("transcription_provider_error") from None

    async def close(self):
        close = getattr(self.http, "aclose", None)
        if close is not None:
            await close()
