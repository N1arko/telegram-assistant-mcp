import base64
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from telegram_assistant.media import (
    prepare_outbound_media, MAX_OUTBOUND_MEDIA_BYTES,
)
from telegram_assistant.security import Denied, Grant, Policy, Quotas, RateGate
from telegram_assistant.service import SCOPES, Service


PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/"
    "m6kAAAAASUVORK5CYII="
)


def encoded(data):
    return base64.b64encode(data).decode("ascii")


class OutboundMediaValidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_photo_checks_signature_dimensions_and_private_tempfile(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch("telegram_assistant.media._probe", AsyncMock(return_value={"streams": [
                    {"codec_type": "video", "width": 1, "height": 1}]})):
                result = await prepare_outbound_media(
                    {"media_type": "photo", "data_base64": encoded(PNG), "caption": "synthetic"},
                    Path(folder), remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(result.mime_type, "image/png")
            self.assertEqual(result.filename, "attachment.png")
            self.assertEqual(result.path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result.path.read_bytes(), PNG)

    async def test_photo_rejects_fake_mime_and_dimensions_over_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(Denied) as raised:
                await prepare_outbound_media({"media_type": "photo", "data_base64": encoded(b"%PDF-1.7")},
                                             Path(folder), remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(raised.exception.code, "unsupported_image_format")
            with patch("telegram_assistant.media._probe", AsyncMock(return_value={"streams": [
                    {"codec_type": "video", "width": 12000, "height": 12000}]})):
                with self.assertRaises(Denied) as raised:
                    await prepare_outbound_media({"media_type": "photo", "data_base64": encoded(PNG)},
                                                 Path(folder), remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(raised.exception.code, "image_too_many_pixels")

    async def test_document_sniffs_mime_and_rejects_mismatched_extension_or_path(self):
        with tempfile.TemporaryDirectory() as folder:
            source = {"media_type": "document", "data_base64": encoded(b"%PDF-1.7\nsynthetic"),
                      "filename": "brief.pdf"}
            result = await prepare_outbound_media(source, Path(folder), remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(result.mime_type, "application/pdf")
            self.assertEqual(result.filename, "brief.pdf")
            with self.assertRaises(Denied) as raised:
                await prepare_outbound_media({**source, "filename": "brief.png"}, Path(folder),
                                             remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(raised.exception.code, "media_mime_mismatch")
            with self.assertRaises(Denied) as raised:
                await prepare_outbound_media({**source, "filename": "../brief.pdf"}, Path(folder),
                                             remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(raised.exception.code, "invalid_media_filename")

    async def test_invalid_base64_caption_and_byte_budget_fail_closed(self):
        with tempfile.TemporaryDirectory() as folder:
            for item, remaining, code in [
                ({"media_type": "document", "data_base64": "**"}, MAX_OUTBOUND_MEDIA_BYTES, "invalid_media_base64"),
                ({"media_type": "document", "data_base64": encoded(b"x"), "caption": "😀" * 513},
                 MAX_OUTBOUND_MEDIA_BYTES, "invalid_media_caption"),
                ({"media_type": "document", "data_base64": encoded(b"xx")}, 1, "media_too_large"),
            ]:
                with self.subTest(code=code):
                    with self.assertRaises(Denied) as raised:
                        await prepare_outbound_media(item, Path(folder), remaining_bytes=remaining)
                    self.assertEqual(raised.exception.code, code)

    async def test_sticker_and_video_guards_use_container_and_actual_dimensions(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            webp_payload = b"\x00"
            webp = (b"RIFF" + (14).to_bytes(4, "little") + b"WEBP" + b"VP8 " +
                    len(webp_payload).to_bytes(4, "little") + webp_payload + b"\x00")
            with patch("telegram_assistant.media._probe", AsyncMock(return_value={"streams": [
                    {"codec_type": "video", "width": 512, "height": 512}]})):
                sticker = await prepare_outbound_media(
                    {"media_type": "sticker", "sticker_emoji": "🙂", "filename": "one.webp",
                     "data_base64": encoded(webp)},
                    root, remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(sticker.mime_type, "image/webp")
            with patch("telegram_assistant.media._probe", AsyncMock(return_value={"streams": [
                    {"codec_type": "video", "width": 513, "height": 512}]})):
                with self.assertRaises(Denied) as raised:
                    await prepare_outbound_media(
                        {"media_type": "sticker", "sticker_emoji": "🙂", "filename": "two.webp",
                         "data_base64": encoded(webp)},
                        root, remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(raised.exception.code, "sticker_dimensions_exceeded")

            animated_payload = b"\x02"
            animated_webp = (b"RIFF" + (14).to_bytes(4, "little") + b"WEBP" + b"VP8X" +
                             len(animated_payload).to_bytes(4, "little") + animated_payload + b"\x00")
            with self.assertRaises(Denied) as raised:
                await prepare_outbound_media(
                    {"media_type": "sticker", "sticker_emoji": "🙂", "filename": "animated.webp",
                     "data_base64": encoded(animated_webp)},
                    root, remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(raised.exception.code, "animated_stickers_unsupported")

            probe = {"streams": [{"codec_type": "video", "width": 32, "height": 32}],
                     "format": {"format_name": "mov,mp4,m4a,3gp,3g2,mj2", "duration": "301"}}
            with patch("telegram_assistant.media._probe", AsyncMock(return_value=probe)):
                with self.assertRaises(Denied) as raised:
                    await prepare_outbound_media(
                        {"media_type": "video", "filename": "duration.mp4",
                         "data_base64": encoded(b"0000ftypsynthetic")},
                        root, remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(raised.exception.code, "media_too_long")

    @unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg/FFprobe unavailable")
    async def test_synthetic_telegram_style_voice_and_video_are_probed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ogg = root / "synthetic.ogg"
            subprocess.run([shutil.which("ffmpeg"), "-nostdin", "-v", "error", "-f", "lavfi", "-i",
                            "anullsrc=r=48000:cl=mono", "-t", "1", "-c:a", "libopus", "-b:a", "16k",
                            "-f", "ogg", str(ogg)], check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            voice = await prepare_outbound_media({"media_type": "voice", "data_base64": encoded(ogg.read_bytes())},
                                                  root, remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(voice.mime_type, "audio/ogg")
            self.assertTrue(voice.voice)
            self.assertEqual(voice.filename, "attachment.ogg")
            self.assertLessEqual(voice.duration, 1.2)
            # Exercise the pinned Telethon upload-media construction without
            # connecting or transmitting this synthetic OGG/Opus fixture.
            from telethon import TelegramClient, types
            client = TelegramClient(None, 123456, "a" * 32)
            client.upload_file = AsyncMock(return_value=types.InputFile(
                id=1, parts=1, name=voice.filename, md5_checksum=""))
            _, telegram_media, as_image = await client._file_to_media(
                str(voice.path), mime_type=voice.mime_type, voice_note=True,
                attributes=[types.DocumentAttributeFilename(voice.filename),
                            types.DocumentAttributeAudio(duration=int(voice.duration), voice=True)])
            self.assertFalse(as_image)
            self.assertIsInstance(telegram_media, types.InputMediaUploadedDocument)
            audio_attribute = next(a for a in telegram_media.attributes
                                   if isinstance(a, types.DocumentAttributeAudio))
            self.assertTrue(audio_attribute.voice)
            self.assertEqual(telegram_media.mime_type, "audio/ogg")
            client.session.close()

            mp4 = root / "synthetic.mp4"
            subprocess.run([shutil.which("ffmpeg"), "-nostdin", "-v", "error", "-f", "lavfi", "-i",
                            "color=c=red:s=32x32:r=2", "-t", "1", "-c:v", "mpeg4", "-pix_fmt",
                            "yuv420p", "-movflags", "+faststart", str(mp4)], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            video = await prepare_outbound_media({"media_type": "video", "data_base64": encoded(mp4.read_bytes())},
                                                  root, remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(video.mime_type, "video/mp4")
            self.assertEqual((video.width, video.height), (32, 32))
            self.assertLessEqual(video.duration, 1.2)

            gif = root / "synthetic.gif"
            subprocess.run([shutil.which("ffmpeg"), "-nostdin", "-v", "error", "-f", "lavfi", "-i",
                            "color=c=blue:s=32x32:r=2", "-t", "1", "-loop", "0", str(gif)],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            animation = await prepare_outbound_media(
                {"media_type": "animation", "data_base64": encoded(gif.read_bytes())}, root,
                remaining_bytes=MAX_OUTBOUND_MEDIA_BYTES)
            self.assertEqual(animation.mime_type, "image/gif")
            self.assertLessEqual(animation.duration, 1.2)


class OutboundMediaServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.quotas = Quotas(Path(self.temp.name) / "quota" / "send.sqlite")
        self.grant = Grant(42, 200000, 12, 2, 2)
        self.backend = FakeMediaBackend()
        self.service = Service(self.backend, Policy([self.grant]), self.quotas,
                               gate=RateGate(limit=1000), clock=lambda: 100000)
        self.scope = SCOPES.set(frozenset({"telegram:read", "telegram:send"}))

    async def asyncTearDown(self):
        SCOPES.reset(self.scope)
        self.quotas.close()
        self.temp.cleanup()

    async def test_single_document_reuses_grant_and_cleans_private_file(self):
        result = await self.service.invoke("send_media", peer_id=42, items=[
            {"media_type": "document", "filename": "note.pdf",
             "data_base64": encoded(b"%PDF-1.7\nsynthetic"), "caption": "Approved"}])
        self.assertEqual(result, {"sent": True, "peer_id": 42, "message_ids": [77],
                                  "media_count": 1, "album": False})
        self.assertEqual(self.backend.calls[0][0], 42)
        sent_path = self.backend.paths[0]
        self.assertFalse(sent_path.exists())
        self.assertEqual(self.backend.file_modes, [0o600])
        self.assertEqual(self.quotas.db.execute("SELECT count(*) FROM attempts").fetchone()[0], 1)

    async def test_album_counts_each_message_in_existing_quota(self):
        item = {"media_type": "photo", "data_base64": encoded(PNG)}
        with patch("telegram_assistant.media._probe", AsyncMock(return_value={"streams": [
                {"codec_type": "video", "width": 1, "height": 1}]})):
            result = await self.service.invoke("send_media", peer_id=42, items=[item, item])
        self.assertNotIn("error", result, result)
        self.assertEqual(result["message_ids"], [77, 78])
        self.assertTrue(result["album"])
        self.assertEqual(self.quotas.db.execute("SELECT count(*) FROM attempts").fetchone()[0], 2)
        denied = await self.service.invoke("send_media", peer_id=42, items=[item])
        self.assertEqual(denied["error"], "send_quota_exceeded")
        self.assertEqual(self.backend.calls.__len__(), 1)

    async def test_unknown_delivery_consumes_quota_and_is_not_retried(self):
        self.service.policy = Policy([Grant(42, 200000, 12, 1, 2)])
        self.backend.fail = True
        item = {"media_type": "document", "data_base64": encoded(b"%PDF-1.7")}
        first = await self.service.invoke("send_media", peer_id=42, items=[item])
        second = await self.service.invoke("send_media", peer_id=42, items=[item])
        self.assertEqual(first, {"error": "delivery_unknown"})
        self.assertEqual(second, {"error": "send_quota_exceeded"})
        self.assertEqual(len(self.backend.calls), 1)

    async def test_first_contact_only_grant_cannot_send_media(self):
        self.service.policy = Policy([Grant(42, 200000, 12, 1, 2,
                                              selector="first_contact", first_contact=True)])
        result = await self.service.invoke("send_media", peer_id=42,
            items=[{"media_type": "document", "data_base64": encoded(b"%PDF-1.7")}])
        self.assertEqual(result["error"], "send_denied")
        self.assertEqual(self.backend.calls, [])


class FakeMediaBackend:
    def __init__(self):
        self.calls = []
        self.paths = []
        self.file_modes = []
        self.fail = False

    async def resolve(self, target):
        return target, "user"

    async def is_human_user(self, target):
        return True

    async def message(self, target, message_id):
        return {"id": message_id}

    async def send_media_files(self, target, files, reply_to):
        self.calls.append((target, files, reply_to))
        self.paths.extend(item.path for item in files)
        self.file_modes.extend(item.path.stat().st_mode & 0o777 for item in files)
        if self.fail:
            raise TimeoutError
        return list(range(77, 77 + len(files)))
