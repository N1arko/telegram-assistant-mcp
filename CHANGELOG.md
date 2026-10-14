# Changelog

## 0.1.2 — 2026-10-14

### Added

- Include attachment media types in message results, add native audio retrieval, and add bounded local text extraction for PDF, DOCX, and plain-text documents.
- Keep transcription disabled by default; document and audio retrieval do not call external providers.

### Safety and compatibility

- Bound PDF worker output while reading and terminate/reap the child on timeout or cancellation.
- Reject DOCX DTD/entity declarations across XML encodings, including UTF-16.
- Native audio transport is tested through the MCP SDK and HTTP. ChatGPT playback and speech understanding remain a separate client acceptance check.

## 0.1.1 — 2026-10-09

### Added

- Add the opt-in `quota_mode: "global_only"` policy mode. It skips per-recipient rate and daily quotas while retaining global ceilings and all permission checks.
- Add a CLI option for selecting the quota mode, preserve the existing mode by default, and document the behavior in English and Russian.

### Compatibility

- Version 1 and 2 policy files without `quota_mode` continue to use `recipient_and_global`.
