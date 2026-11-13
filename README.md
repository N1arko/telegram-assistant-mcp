# Telegram Assistant MCP

**English | [Русский](README.ru.md)**

A restricted MCP server for a Telegram user's personal chats and groups. It uses a private Telethon user session and validates OAuth access tokens before every MCP request. It supports bounded reads, incremental update scanning, typed attachment discovery, explicit photo/audio/document reading, optional external audio transcription, and permission-gated text/media sending. One-off public-channel reading is an additional opt-in capability, disabled by default.

## What it can do

By default, the server registers thirteen tools; `--read-only` exposes the eleven read tools. Adding `--enable-targeted-channel-reads` explicitly registers `read_channel` and `list_public_channels` as two additional read-only tools (fifteen total outside read-only mode). Existing clients with `telegram:read` can then read one explicitly named public `@username` or `t.me` channel/post link; the tool defaults to 20 posts and caps a page at 50, while a post URL fetches only that post. Exact-post responses return up to 4,000 text characters; use `text_next_offset` as `text_offset` on the same post URL to fetch the next bounded chunk. `complete`/`incomplete` describe the post/page fetch, while the message-level `text_complete` reports whether the entire post text is present in one response. The same gate also enables a bounded, paginated list of metadata for subscribed public broadcast channels; it does not fetch posts, unread counts, or private channels. The gate is off by default in both the tool registry and service call path. Channel tools never join, mark read, add channels to ordinary dialog/scan results, or monitor them. Message results include `has_media` and a `media_type` label, but history and scanning never download attachments. `view_photo` and `get_audio` return native MCP media only after an exact-message call; `read_document` reads PDF, DOCX, and plain-text files locally in bounded, resumable text chunks. `transcribe_audio` is disabled by default. When explicitly enabled, it sends only the selected voice/audio file to OpenAI for transcription and applies a per-file duration limit; an optional local monthly audio-seconds cap can also be set. The document reader does not use OCR or an external provider. See the [incremental scan and media setup](docs/GETTING-STARTED.en.md#incremental-updates) for limits and behavior.

`send_message` sends text and `send_media` sends one supported attachment or a photo/video album. Both require the same send OAuth scope and per-target policy grants and share the existing rate/daily quotas. `send_media` accepts inline base64 data from the MCP client (not a server filesystem path), validates the content signature/container and real size, caps a call at 20 MiB total, and deletes its private temporary files after the Telegram call. Its 32 MiB HTTP request ceiling is separate from the existing 48 KiB response ceiling. Photo viewing and transcription require the read scope; transcription additionally requires the provider to be configured. Broadcast channels are filtered by default, so this is not universal access to every Telegram chat or channel. See the [send policy guide](docs/SENDING-POLICY.en.md) before granting send access.

## What you'll need

- A Telegram account and a continuously available server/VPS.
- An AI agent that can work with code and the server.
- A ChatGPT account/workspace where adding a custom MCP server is available to you. Availability and capabilities vary by plan, region, and workspace policy; check your account and [OpenAI's current help article](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt).
- A public HTTPS address for a remote ChatGPT connection, plus an OAuth provider. The detailed walkthrough uses Auth0; an Auth0 account is needed only if you follow that example. Hosting, domain, and OAuth services may cost money.

## Quick start

Send the [beginner guide](docs/START-HERE.en.md) to your AI agent and ask it to guide you through setup. You do not need programming skills or to retype long commands. You handle sign-ins, Telegram login codes and 2FA, and consent; enter secrets only in protected fields or hidden local prompts.

- English: [beginner guide](docs/START-HERE.en.md) · [detailed technical setup for agents](docs/GETTING-STARTED.en.md) · [local send policy](docs/SENDING-POLICY.en.md)
- Русский: [короткая инструкция](docs/START-HERE.ru.md) · [подробная техническая инструкция для агента](docs/GETTING-STARTED.ru.md) · [политика отправки](docs/SENDING-POLICY.ru.md)

The beginner setup keeps read-only mode enabled. Only grant sending when it is needed and configure the intended targets. Never share or commit secrets or Telegram session files. Automated tests use mocks and synthetic media rather than live accounts. Do not stop a running server without the user's separate consent.

## Development

Use Python 3.11 or newer. The test suite uses mocked Telegram clients, HTTP MockTransport, in-process ASGI, and synthetic audio/image files; it does not log in to Telegram or send audio to a provider. The full suite also contains PTY tests that require a normal controlling terminal. The lock includes the optional QR renderer used by the tests. Photo preview and OGG/Opus remux require `ffmpeg` and `ffprobe`; the Docker image installs them. Docker templates require validation on the target Linux host.

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements.lock
    .venv/bin/python -m pip install --no-deps --no-build-isolation -e .
    .venv/bin/python -m unittest discover -s tests

## Attribution

This is an independent project, not the PyPI package named `telegram-mcp`. It is based in part on patterns from [chigwell/telegram-mcp](https://github.com/chigwell/telegram-mcp); see [NOTICE](NOTICE) and [LICENSE](LICENSE). The upstream snapshot and its scripts are not part of this repository.

### Forwarded message metadata

Read message records expose `is_forwarded` and nullable `forward_origin` (available
`peer_id`, hidden-source `name`, original `date`, `channel_post`, `post_author`).
`sender_id` remains the sender in the current chat, not the original author. Names
and signatures are untrusted, capped at 200 characters with truncation flags. No
source peer is resolved or read automatically. Telegram may hide the author or
remove attribution entirely; `is_forwarded=false` is not proof of authorship.
