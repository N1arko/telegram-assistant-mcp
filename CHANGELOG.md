# Changelog

## 0.1.3 — 2026-11-10

### Added

- Add an opt-in, bounded read path for one explicitly named public broadcast channel or exact public post. Its gate is off by default; reads stay separate from dialog listing and recurring chat scans, and never join or acknowledge posts.
- Add a gated, paginated `list_public_channels` metadata tool for subscribed public broadcast channels. It omits post history, unread counts, private channels, and remains separate from normal dialog and scan results.

### Fixed

- Read complete extracted PDF/DOCX/TXT text through character offsets, bounded chunk sizes, explicit continuation/completeness fields, and an optional SHA-256 guard against replaced attachments. Existing two-argument calls remain compatible.
- Preserve exact public-post pagination and the deployed bounded metadata-only diagnostic instrumentation in the unified source release.
- Cover long Unicode documents, exact boundaries, empty pages, changed files, invalid arguments, and MCP HTTP round trips with synthetic tests.

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
