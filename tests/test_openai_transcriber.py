import tempfile
import unittest
from pathlib import Path

import httpx

from telegram_assistant.media import OpenAITranscriber
from telegram_assistant.security import Denied


class OpenAITranscriberTests(unittest.IsolatedAsyncioTestCase):
    async def test_mocked_multipart_contains_only_selected_synthetic_audio(self):
        selected = b"synthetic Telegram-style audio bytes"
        captured = []

        def handler(request):
            captured.append(request)
            return httpx.Response(200, json={"text": "synthetic transcript"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False,
                                  trust_env=False)
        transcriber = OpenAITranscriber("sk-synthetic-test-key-only", http=client)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "audio.webm"
            source.write_bytes(selected)
            result = await transcriber.transcribe(source, filename="telegram-audio.webm",
                                                  mime_type="audio/webm")
        await transcriber.close()
        self.assertEqual(result, "synthetic transcript")
        self.assertEqual(len(captured), 1)
        request = captured[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(str(request.url), "https://api.openai.com/v1/audio/transcriptions")
        self.assertEqual(request.headers["authorization"], "Bearer sk-synthetic-test-key-only")
        self.assertIn(b"gpt-4o-mini-transcribe", request.content)
        self.assertIn(b"telegram-audio.webm", request.content)
        self.assertIn(selected, request.content)

    async def test_provider_redirect_and_oversized_responses_fail_safely(self):
        requests = []

        def redirect(request):
            requests.append(request)
            return httpx.Response(307, headers={"location": "https://outside.example/"})

        client = httpx.AsyncClient(transport=httpx.MockTransport(redirect), follow_redirects=False,
                                  trust_env=False)
        transcriber = OpenAITranscriber("sk-synthetic-test-key-only", http=client)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "audio.wav"
            source.write_bytes(b"synthetic")
            with self.assertRaises(Denied) as raised:
                await transcriber.transcribe(source, filename="audio.wav", mime_type="audio/wav")
        await transcriber.close()
        self.assertEqual(raised.exception.code, "transcription_provider_error")
        self.assertEqual(len(requests), 1)

        client = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=b"x" * (64 * 1024 + 1),
                                           headers={"content-type": "application/json"})),
            follow_redirects=False, trust_env=False)
        transcriber = OpenAITranscriber("sk-synthetic-test-key-only", http=client)
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "audio.wav"
            source.write_bytes(b"synthetic")
            with self.assertRaises(Denied) as raised:
                await transcriber.transcribe(source, filename="audio.wav", mime_type="audio/wav")
        await transcriber.close()
        self.assertEqual(raised.exception.code, "transcription_response_too_large")
