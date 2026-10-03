import shutil
import sys
import subprocess
import tempfile
import unittest
import wave
import asyncio
from pathlib import Path
from types import ModuleType, SimpleNamespace as NS
from unittest.mock import AsyncMock

from telegram_assistant.media import (ImageResult, MAX_IMAGE_PREVIEW_BYTES,
                                      MAX_IMAGE_PREVIEW_EDGE, MediaCache,
                                      TranscriptionConfig,
                                      prepare_audio, preview_image, sniff_audio_kind,
                                      sniff_image_mime, _run_bounded)
from telegram_assistant.security import Denied, Quotas, RateGate
from telegram_assistant.service import SCOPES, Service
from telegram_assistant.backend import TelethonBackend


def make_wav(path, seconds=1):
    with wave.open(str(path), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(16000)
        output.writeframes(b"\x00\x00" * (16000 * seconds))


def ffmpeg(*args):
    return subprocess.run([shutil.which("ffmpeg"), "-nostdin", "-v", "error", *args],
                          check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class MediaHelpersTests(unittest.IsolatedAsyncioTestCase):
    async def test_subprocess_timeout_includes_wait_after_stdout_closes(self):
        class EmptyOutput:
            async def read(self, size):
                return b""

        class SlowExit:
            def __init__(self):
                self.stdout = EmptyOutput()
                self.returncode = None

            async def wait(self):
                if self.returncode is None:
                    await asyncio.sleep(1)
                return self.returncode

            def kill(self):
                self.returncode = -9

        process = SlowExit()
        from unittest.mock import patch, AsyncMock
        with patch("telegram_assistant.media.asyncio.create_subprocess_exec",
                   AsyncMock(return_value=process)):
            with self.assertRaises(Denied) as raised:
                await _run_bounded(["synthetic"], timeout=0.01, max_stdout=10)
        self.assertEqual(raised.exception.code, "media_processing_timeout")
        self.assertEqual(process.returncode, -9)

    def test_audio_and_image_format_sniffing_uses_file_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            wav = root / "audio.data"
            make_wav(wav)
            self.assertEqual(sniff_audio_kind(wav), "wav")
            image = root / "image.data"
            image.write_bytes(b"\xff\xd8\xff" + b"x" * 20)
            self.assertEqual(sniff_image_mime(image), "image/jpeg")
            bad = root / "fake.ogg"
            bad.write_bytes(b"OggS" + b"no opus head")
            with self.assertRaises(Denied) as raised:
                sniff_audio_kind(bad)
            self.assertEqual(raised.exception.code, "unsupported_audio_format")

    @unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg/FFprobe unavailable")
    async def test_telegram_style_ogg_opus_is_remuxed_to_supported_webm_without_decoding(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ogg = root / "synthetic-voice.ogg"
            ffmpeg("-f", "lavfi", "-i", "anullsrc=r=48000:cl=mono", "-t", "1",
                   "-c:a", "libopus", "-b:a", "16k", "-f", "ogg", str(ogg))
            self.assertEqual(sniff_audio_kind(ogg), "ogg-opus")
            webm, filename, mime, duration = await prepare_audio(ogg, root)
            self.assertEqual((filename, mime), ("telegram-audio.webm", "audio/webm"))
            self.assertGreater(webm.stat().st_size, 0)
            self.assertLessEqual(duration, 1.1)
            # Probe the local synthetic file only; this never invokes a provider.
            probe = subprocess.run([shutil.which("ffprobe"), "-v", "error", "-select_streams", "a:0",
                                    "-show_entries", "stream=codec_name", "-of", "default=nw=1:nk=1",
                                    str(webm)], check=True, capture_output=True, text=True)
            self.assertEqual(probe.stdout.strip(), "opus")
            with self.assertRaises(Denied) as raised:
                await prepare_audio(ogg, root, max_seconds=0.5)
            self.assertEqual(raised.exception.code, "audio_too_long")

    @unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg/FFprobe unavailable")
    async def test_photo_preview_is_jpeg_bounded_and_resized(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "synthetic-photo.jpg"
            ffmpeg("-f", "lavfi", "-i", "testsrc2=size=1920x1080:rate=1", "-frames:v", "1",
                   "-q:v", "2", str(source))
            self.assertEqual(sniff_image_mime(source), "image/jpeg")
            result = await preview_image(source)
            self.assertIsInstance(result, ImageResult)
            self.assertEqual(result.mime_type, "image/jpeg")
            self.assertTrue(result.data.startswith(b"\xff\xd8\xff"))
            self.assertLessEqual(len(result.data), MAX_IMAGE_PREVIEW_BYTES)
            preview = root / "preview.jpg"
            preview.write_bytes(result.data)
            probe = subprocess.run([shutil.which("ffprobe"), "-v", "error", "-select_streams", "v:0",
                                    "-show_entries", "stream=width,height", "-of", "csv=s=x:p=0",
                                    str(preview)], check=True, capture_output=True, text=True)
            width, height = map(int, probe.stdout.strip().split("x"))
            self.assertLessEqual(max(width, height), MAX_IMAGE_PREVIEW_EDGE)

    def test_cache_is_ttl_and_byte_bounded(self):
        now = [10.0]
        cache = MediaCache(clock=lambda: now[0], ttl=5, max_bytes=8)
        cache.put("one", "12345")
        cache.put("two", "abcd")
        self.assertIsNone(cache.get("one"))
        self.assertEqual(cache.get("two"), "abcd")
        now[0] += 6
        self.assertIsNone(cache.get("two"))


class MediaBackend:
    def __init__(self, media_bytes, metadata):
        self.media_bytes, self.metadata = media_bytes, metadata
        self.resolve = AsyncMock(return_value=(42, "user"))
        self.fetch_calls = 0

    async def fetch_media_file(self, target, message_id, *, kind, destination, max_bytes):
        self.fetch_calls += 1
        if len(self.media_bytes) > max_bytes:
            raise Denied("media_too_large")
        destination.write_bytes(self.media_bytes)
        return dict(self.metadata)


class FakeTranscriber:
    def __init__(self, transcript="synthetic transcript"):
        self.transcript = transcript
        self.calls = []

    async def transcribe(self, path, *, filename, mime_type):
        self.calls.append((path, filename, mime_type, path.read_bytes()))
        return self.transcript


class MediaServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scope = SCOPES.set(frozenset({"telegram:read"}))
        self.tmp = tempfile.TemporaryDirectory()

    async def asyncTearDown(self):
        SCOPES.reset(self.scope)
        self.tmp.cleanup()

    async def test_transcription_stays_off_and_does_not_fetch_audio(self):
        backend = MediaBackend(b"private", {"declared_duration": 1, "declared_mime": "audio/wav"})
        service = Service(backend, gate=RateGate(limit=100))
        result = await service.invoke("transcribe_audio", peer_id=42, message_id=4)
        self.assertEqual(result, {"error": "transcription_disabled"})
        self.assertEqual(backend.fetch_calls, 0)

    async def test_transcript_cache_and_persistent_monthly_budget(self):
        source = Path(self.tmp.name) / "source.wav"
        make_wav(source)
        backend = MediaBackend(source.read_bytes(),
                               {"declared_duration": 1, "declared_mime": "audio/wav"})
        quota_path = Path(self.tmp.name) / "runtime" / "quotas.sqlite"
        quotas = Quotas(quota_path)
        transcriber = FakeTranscriber("a safe synthetic transcript")
        service = Service(backend, quotas=quotas, gate=RateGate(limit=100),
                          clock=lambda: 1_800_000_000,
                          transcription=TranscriptionConfig("openai", "sk-unit-test-key-123456789",
                                                            monthly_seconds=1),
                          transcriber=transcriber)
        first = await service.invoke("transcribe_audio", peer_id=42, message_id=5)
        second = await service.invoke("transcribe_audio", peer_id=42, message_id=5)
        self.assertEqual(first["transcript"], "a safe synthetic transcript")
        self.assertFalse(first["cached"])
        self.assertTrue(second["cached"])
        self.assertEqual(backend.fetch_calls, 1)
        self.assertEqual(len(transcriber.calls), 1)
        self.assertEqual(transcriber.calls[0][1:], ("telegram-audio.wav", "audio/wav", source.read_bytes()))
        self.assertEqual(quotas.db.execute("SELECT seconds FROM transcription_usage").fetchone()[0], 1)
        quotas.close()

    @unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg/FFprobe unavailable")
    async def test_photo_preview_is_returned_only_on_explicit_request_and_cached(self):
        source = Path(self.tmp.name) / "photo.jpg"
        ffmpeg("-f", "lavfi", "-i", "color=c=blue:s=640x480", "-frames:v", "1", str(source))
        backend = MediaBackend(source.read_bytes(), {})
        service = Service(backend, gate=RateGate(limit=100))
        first = await service.invoke("view_photo", peer_id=42, message_id=3)
        second = await service.invoke("view_photo", peer_id=42, message_id=3)
        self.assertIsInstance(first, ImageResult)
        self.assertLessEqual(len(first.data), MAX_IMAGE_PREVIEW_BYTES)
        self.assertEqual(second, first)
        self.assertEqual(backend.fetch_calls, 1)


class TelethonMediaDownloadTests(unittest.IsolatedAsyncioTestCase):
    class AudioAttribute:
        def __init__(self, duration=2, voice=True):
            self.duration, self.voice = duration, voice

    class PhotoLocation:
        def __init__(self, **values):
            self.values = values

    async def _with_fake_telethon(self, message, chunks):
        module = ModuleType("telethon")
        module.types = NS(DocumentAttributeAudio=self.AudioAttribute,
                          InputPhotoFileLocation=self.PhotoLocation)
        client = NS(get_messages=AsyncMock(return_value=message))
        calls = []
        def iter_download(location, **kwargs):
            calls.append((location, kwargs))
            async def stream():
                for chunk in chunks:
                    yield chunk
            return stream()
        client.iter_download = iter_download
        backend = TelethonBackend(client)
        backend.peers[42] = object()
        return module, backend, client, calls

    async def test_exact_audio_message_download_is_bounded_and_private(self):
        with tempfile.TemporaryDirectory() as folder:
            document = NS(attributes=[self.AudioAttribute(2, True)], size=3, mime_type="audio/ogg")
            message = NS(id=9, document=document, photo=None)
            module, backend, client, calls = await self._with_fake_telethon(message, [b"ab", b"c"])
            destination = Path(folder) / "audio"
            from unittest.mock import patch
            with patch.dict(sys.modules, {"telethon": module}):
                metadata = await backend.fetch_media_file(42, 9, kind="audio", destination=destination, max_bytes=3)
            self.assertEqual(metadata["declared_mime"], "audio/ogg")
            self.assertEqual(metadata["declared_duration"], 2)
            self.assertEqual(destination.read_bytes(), b"abc")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
            self.assertEqual(calls[0][1]["limit"], 1)
            self.assertEqual(calls[0][1]["file_size"], 3)
            client.get_messages.assert_awaited_once()
            self.assertEqual(client.get_messages.await_args.kwargs, {"ids": 9})

    async def test_audio_fetch_rejects_id_size_and_media_type_mismatch(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder) / "audio"
            message = NS(id=10, document=NS(attributes=[self.AudioAttribute()], size=3,
                                            mime_type="audio/ogg"), photo=None)
            module, backend, _, _ = await self._with_fake_telethon(message, [b"abc"])
            from unittest.mock import patch
            with patch.dict(sys.modules, {"telethon": module}):
                with self.assertRaises(Denied) as raised:
                    await backend.fetch_media_file(42, 9, kind="audio", destination=destination, max_bytes=3)
                self.assertEqual(raised.exception.code, "message_missing")
                message.id = 9
                with self.assertRaises(Denied) as raised:
                    await backend.fetch_media_file(42, 9, kind="audio", destination=destination, max_bytes=2)
                self.assertEqual(raised.exception.code, "audio_too_large")
                with self.assertRaises(Denied) as raised:
                    await backend.fetch_media_file(42, 9, kind="photo", destination=destination, max_bytes=3)
                self.assertEqual(raised.exception.code, "media_type_unsupported")

    async def test_photo_download_selects_only_one_sized_thumbnail(self):
        with tempfile.TemporaryDirectory() as folder:
            photo = NS(id=12, access_hash=44, file_reference=b"ref", sizes=[
                NS(type="s", w=320, h=240, size=3), NS(type="x", w=1600, h=1200, size=9)])
            message = NS(id=10, photo=photo, document=None)
            module, backend, _, calls = await self._with_fake_telethon(message, [b"ab", b"c"])
            destination = Path(folder) / "photo"
            from unittest.mock import patch
            with patch.dict(sys.modules, {"telethon": module}):
                metadata = await backend.fetch_media_file(42, 10, kind="photo", destination=destination, max_bytes=8)
            self.assertEqual(metadata["size"], 3)
            self.assertEqual(calls[0][0].values["thumb_size"], "s")
            self.assertEqual(destination.read_bytes(), b"abc")


class MediaServiceBudgetTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.scope = SCOPES.set(frozenset({"telegram:read"}))
        self.tmp = tempfile.TemporaryDirectory()

    async def asyncTearDown(self):
        SCOPES.reset(self.scope)
        self.tmp.cleanup()

    async def test_budget_is_reserved_before_call_and_never_refunds_failure(self):
        source = Path(self.tmp.name) / "source.wav"
        make_wav(source)
        backend = MediaBackend(source.read_bytes(), {"declared_duration": 1, "declared_mime": "audio/wav"})
        quotas = Quotas(Path(self.tmp.name) / "state" / "quotas.sqlite")
        transcriber = FakeTranscriber()
        transcriber.transcribe = AsyncMock(side_effect=RuntimeError("synthetic provider detail"))
        service = Service(backend, quotas=quotas, gate=RateGate(limit=100),
                          transcription=TranscriptionConfig("openai", "sk-unit-test-key-123456789",
                                                            monthly_seconds=1),
                          transcriber=transcriber)
        first = await service.invoke("transcribe_audio", peer_id=42, message_id=6)
        quotas.close()
        quotas = Quotas(Path(self.tmp.name) / "state" / "quotas.sqlite")
        service.quotas = quotas
        second = await service.invoke("transcribe_audio", peer_id=42, message_id=7)
        self.assertEqual(first, {"error": "transcription_provider_error"})
        self.assertEqual(second, {"error": "transcription_budget_exceeded"})
        self.assertEqual(transcriber.transcribe.await_count, 1)
        quotas.close()

    async def test_audio_mime_mismatch_blocks_provider(self):
        source = Path(self.tmp.name) / "source.wav"
        make_wav(source)
        backend = MediaBackend(source.read_bytes(), {"declared_duration": 1, "declared_mime": "audio/mpeg"})
        quotas = Quotas(Path(self.tmp.name) / "state" / "quotas.sqlite")
        transcriber = FakeTranscriber()
        service = Service(backend, quotas=quotas, gate=RateGate(limit=100),
                          transcription=TranscriptionConfig("openai", "sk-unit-test-key-123456789",
                                                            monthly_seconds=10),
                          transcriber=transcriber)
        result = await service.invoke("transcribe_audio", peer_id=42, message_id=8)
        self.assertEqual(result, {"error": "audio_mime_mismatch"})
        self.assertEqual(transcriber.calls, [])
        self.assertEqual(quotas.db.execute("SELECT count(*) FROM transcription_usage").fetchone()[0], 0)
        quotas.close()
