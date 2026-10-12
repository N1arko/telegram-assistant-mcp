# Local send policy

**English | [Русский](SENDING-POLICY.ru.md)**

Text and media sending are disabled by default. The local operator policy is a technical
barrier in addition to the assistant's check that a user's instruction is
current and applies to the recipient and message. It does not encode semantic
rules such as “reply only when someone asks about a meeting.” The policy editor
is a local command-line tool; it is not exposed through MCP.

## Policy file

Use a policy file outside the source repository. Its parent directory and the
file must belong to the current OS user and be private to that user. The editor
resolves ancestor aliases before checking the destination, rejects policy-file
symlinks and paths inside a Git repository, and writes updates atomically.
Never commit a live policy file.

Start from `config/policy.example.json`. It has no grants or denials, defaults
to `quota_mode: "recipient_and_global"`, and sets a global ceiling of 5 sends
per minute and 100 per day. Each recipient grant or rule defaults to 1 send per
minute and 20 per day, with a 4,096 UTF-16-unit message limit. In the default
mode, both recipient and global ceilings apply, and the lowest applicable
ceiling wins. A version 2 policy can opt into `quota_mode: "global_only"` to
skip recipient-level rate and daily checks. Global ceilings, explicit grants
and denials, OAuth scope checks, and the assistant's separate semantic
permission check still apply. Version 1 and 2 policy files that omit
`quota_mode` retain the `recipient_and_global` behavior.

## Selectors and denials

Version 2 policies support these selectors:

- `peer`: one exact peer ID;
- `all_human_dms`: human personal users, excluding bots and the account itself;
- `group_ids`: only the listed group IDs;
- `all_groups`: every eligible group, an intentionally broad rule;
- `first_contact`: eligibility to reply to a specific verified first inbound
  message from a human user.

Broadcast channels, bots, and self are not eligible. An active exact-peer
denial always overrides grants and selectors. With no active matching grant,
sending is denied.

The same existing `send_message` grants also authorize `send_media`; no separate
grant format or OAuth scope is introduced. First-contact-only grants cannot send
media. `send_media` accepts one attachment or a 2–10 item photo/video album. It
checks each caption against the same `max_chars` grant and charges one rate/daily
quota unit for every resulting Telegram message. Failed sends still consume the
reserved quota. An uncertain result must be checked manually and never retried.

Supported single items are JPEG/PNG photos, MP4/WebM videos, documents, MP3,
MP4/M4A, WAV, WebM, or OGG/Opus audio, OGG/Opus voice notes, GIF animations,
and static WebP stickers. Per call, binary data is capped
at 20 MiB; photo input is at most 8 MiB and 12 megapixels; video/GIF frames are
at most 12 megapixels; audio, voice, video, and GIFs are at most five minutes.
Stickers are static WebP up to 512 KiB and
512×512 pixels. Media is supplied inline as base64 by the MCP client and held
only in a private temporary directory while sending.

`first_contact` only establishes eligibility. The send call must provide the
same message ID as `reply_to`; the service verifies that it is an incoming
message from that user and the oldest message currently available in that
dialog. If history is incomplete or the check fails, sending is denied. Remote
deletions cannot be proven, so this is a check of currently available history.
An attempted first-contact reply is reserved before sending. Replays are
blocked; an unknown delivery outcome must be checked manually and is not
retried automatically.

## Local commands

After installing the project, use `telegram-assistant-policy` to inspect or
edit the local policy. Replace the illustrative peer ID and timestamp below
with values you have independently verified; omitting `--expires-at` makes a
grant permanent.

```sh
telegram-assistant-policy --policy /secure/private/policy.json validate
telegram-assistant-policy --policy /secure/private/policy.json grant-peer \
  --peer-id 123456789 --expires-at 1893456000
telegram-assistant-policy --policy /secure/private/policy.json deny-peer \
  --peer-id 123456789
telegram-assistant-policy --policy /secure/private/policy.json revoke-peer \
  --peer-id 123456789
```

To grant a selector, use `grant-rule --selector` with one of the selector names
above. Repeat `--peer-id` for each member of a `group_ids` rule. An
`all_groups` rule covers every eligible group. Review that scope carefully
before creating it. Use `revoke-rule --rule-id` to remove a rule. `allow-peer`
removes an exact-peer denial; it does not create a grant. Use
`set-global-quotas --per-minute N --per-day N` to change the global ceiling.
Add `--mode global_only` to skip recipient-level quota checks while retaining
global ceilings; omitting `--mode` preserves the current mode.

The CLI prints only a generic success or failure result and writes the owner-
only policy through an atomic replacement. No policy management tool is
available to an MCP client.

## Forum topics and send failures

`list_forum_topics(peer_id, limit, offset_date, offset_id, offset_topic)` reads one
bounded page (at most 50 topics) from a resolved forum group. Pass all three
fields from `next_offset` to continue. `scan_truncated=true` means Telegram did
not provide enough information for a safe next offset. `get_forum_topic(peer_id,
topic_id)` checks one topic by ID and returns its title, exact group ID, and
closed/deleted state. `get_reply_context` also includes `forum_topic` when its
reply anchor matches a verified topic, even if that anchor message is absent.
Both tools use `telegram:read`, never mark messages read,
and do not download media. Titles and message content are untrusted.

For forum groups, `send_message` and `send_media` require an explicit `topic_id`.
Use `1` for General; for other topics, the server validates the topic against
the resolved group immediately before reserving quota, then sends to its topic
root. A forum `reply_to` alone is not a topic address. Replies to a different
message within a topic currently return `topic_reply_unsupported`; this avoids
losing the topic if that message disappears during sending. Closed, hidden,
missing, deleted, wrong-group, or non-forum topics are rejected before sending.
The topic check does not grant permission: send scope, recipient policy, and
quotas still apply. Topic state can change after validation; Telegram may still
reject the call.

Safe send error codes distinguish `send_scope_required` (missing OAuth send
scope), `recipient_grant_required` (no active matching grant),
`send_policy_denied` (explicit recipient deny), `recipient_not_eligible`
(grant selector does not cover the resolved recipient), `send_quota_exceeded`,
and `send_quota_unavailable`. Telegram's recognized write restrictions return
`telegram_write_forbidden`; recognized topic and address rejections return
`topic_unavailable` or `telegram_address_invalid`. No policy contents, token,
message body, or raw Telegram exception is returned. `send_preflight_unavailable`
means a lookup failed before any send attempt. `delivery_unknown`
includes timeouts and unclassified failures after an attempt; check Telegram
manually and never retry automatically. A historical `send_denied` means the
old server stopped at a local policy or quota-store check before Telegram, but
does not identify which branch.
