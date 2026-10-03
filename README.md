# Telegram Assistant MCP

**English | [Русский](README.ru.md)**

A small MCP server for searching a Telegram user's personal chats and groups. It uses a private Telethon user session and validates OAuth access tokens before every MCP request. Use read-only mode for the setup described here.

## What it can do

In `--read-only` mode, six bounded tools are available: `list_dialogs`, `get_history`, `search_messages`, `get_reply_context`, `view_photo`, and `transcribe_audio`. History only lists media presence; it never downloads attachments. `view_photo` fetches a photo only when called for an exact message and returns a native MCP image preview. `transcribe_audio` is disabled by default. When explicitly enabled, it sends only the selected voice/audio file to OpenAI for transcription and applies a per-file duration limit; an optional local monthly audio-seconds cap can also be set. See the [media setup](docs/GETTING-STARTED.en.md#explicit-media-tools) before enabling it.

The code also contains a separate permission-gated `send_message` path that is unavailable in read-only mode. It is outside this setup, and live Telegram sending has not been verified. Do not enable it for this use. Broadcast channels are filtered by default, so this is not universal access to every Telegram chat or channel.

## What you'll need

- A Telegram account and a continuously available server/VPS.
- An AI agent that can work with code and the server.
- A ChatGPT account/workspace where adding a custom MCP server is available to you. Availability and capabilities vary by plan, region, and workspace policy; check your account and [OpenAI's current help article](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt).
- A public HTTPS address for a remote ChatGPT connection, plus an OAuth provider. The detailed walkthrough uses Auth0; an Auth0 account is needed only if you follow that example. Hosting, domain, and OAuth services may cost money.

## Quick start

Send the [beginner guide](docs/START-HERE.en.md) to your AI agent and ask it to guide you through setup. You do not need programming skills or to retype long commands. You handle sign-ins, Telegram login codes and 2FA, and consent; enter secrets only in protected fields or hidden local prompts.

- English: [beginner guide](docs/START-HERE.en.md) · [detailed technical setup for agents](docs/GETTING-STARTED.en.md) · [local send policy](docs/SENDING-POLICY.en.md)
- Русский: [короткая инструкция](docs/START-HERE.ru.md) · [подробная техническая инструкция для агента](docs/GETTING-STARTED.ru.md) · [политика отправки](docs/SENDING-POLICY.ru.md)

Keep read-only mode enabled. Never share or commit secrets or Telegram session files. Do not use Telegram messages or read-status changes for testing. Do not stop a running server without the user's separate consent.

## Development

Use Python 3.11 or newer. The test suite uses mocked Telegram clients, HTTP MockTransport, in-process ASGI, and synthetic audio/image files; it does not log in to Telegram or send audio to a provider. The full suite also contains PTY tests that require a normal controlling terminal. The lock includes the optional QR renderer used by the tests. Photo preview and OGG/Opus remux require `ffmpeg` and `ffprobe`; the Docker image installs them. Docker templates require validation on the target Linux host.

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements.lock
    .venv/bin/python -m pip install --no-deps --no-build-isolation -e .
    .venv/bin/python -m unittest discover -s tests

## Attribution

This is an independent project, not the PyPI package named `telegram-mcp`. It is based in part on patterns from [chigwell/telegram-mcp](https://github.com/chigwell/telegram-mcp); see [NOTICE](NOTICE) and [LICENSE](LICENSE). The upstream snapshot and its scripts are not part of this repository.
