# Telegram Assistant MCP

A small, read-only MCP server for searching a Telegram user account's personal chats and groups. It uses a private Telethon user session and validates OAuth access tokens before every MCP request.

## What it exposes

The read-only mode exposes four tools: `list_dialogs`, `get_history`, `search_messages`, and `get_reply_context`. Calls are bounded, paginated, and subject to a persistent cooldown. Telegram messages are returned as untrusted data. The server does not expose tools for sending, editing, deleting, joining, marking messages read, or managing permissions in read-only mode.

Broadcast channels are excluded by default. The source contains an internal exact-channel read-only allowlist hook, but it is unset in the public configuration. Do not widen it without verifying the exact channel and creator status. Sending remains default-deny.

## Getting started

Новый пользователь: начните с [короткой инструкции без требований к навыкам разработки](docs/START-HERE.ru.md) и отправьте её своему ИИ-агенту.

Агенту: [подробная инструкция по настройке](docs/GETTING-STARTED.ru.md) описывает Telegram session, OAuth/Auth0, подключение ChatGPT, Docker, TLS и проверку запуска. Пользователь подтверждает входы, коды, разрешения и секретные данные; агент не должен просить отправлять их в чат. Примеры конфигураций содержат только фиктивные значения.

## Tests

Use Python 3.11 or newer. The test suite uses mocked Telegram clients, HTTP MockTransport, and in-process ASGI; it does not log in to Telegram or open a listening socket. The full suite, including fake-login PTY tests, was verified with Python 3.14.6 and all 146 tests passed. PTY tests require a normal controlling terminal. The lock includes the optional QR renderer used by the tests; Docker templates require validation on the target Linux host.

    python3 -m venv .venv
    .venv/bin/python -m pip install -r requirements.lock
    .venv/bin/python -m pip install --no-deps --no-build-isolation -e .
    .venv/bin/python -m unittest discover -s tests

## Attribution

This is an independent project, not the PyPI package named `telegram-mcp`. It is based in part on patterns from [chigwell/telegram-mcp](https://github.com/chigwell/telegram-mcp); see [NOTICE](NOTICE) and [LICENSE](LICENSE). The upstream snapshot and its scripts are not part of this repository.
