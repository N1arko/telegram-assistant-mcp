# Personal WhatsApp MCP

Independent OAuth Streamable HTTP server and loopback Go bridge. Existing deployment source is now versioned together with an optional media compatibility fallback.

`get_media(chat_id, message_id, output_format="base64")` returns JSON text containing base64 bytes, MIME, byte length, SHA-256 and source IDs for clients that cannot accept MCP AudioContent. Default `inline` remains compatible. Maximum 5 MiB; selected-message reads only. Save decoded bytes privately outside Git; do not log payloads. No public media links, new credentials, permissions, external transcription or read receipts.

Run Python tests: `python -m unittest discover -s tests -p 'test_whatsapp*.py'`. Build/test the pinned no-resend Go bridge via `python whatsapp/build.py --test`; never build bypassing the SDK patch.

Deployment examples are in deploy/whatsapp. Account configuration, encrypted state, tokens, pairing and public ingress must be set up separately and are not included here.
