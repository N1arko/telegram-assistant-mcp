# Changelog

## 0.1.1 — 2026-10-09

### Added

- Add the opt-in `quota_mode: "global_only"` policy mode. It skips per-recipient rate and daily quotas while retaining global ceilings and all permission checks.
- Add a CLI option for selecting the quota mode, preserve the existing mode by default, and document the behavior in English and Russian.

### Compatibility

- Version 1 and 2 policy files without `quota_mode` continue to use `recipient_and_global`.
