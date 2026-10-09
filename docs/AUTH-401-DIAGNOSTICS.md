# Temporary OAuth transport diagnostics

Live mode can be started with `--auth-diagnostics-until-epoch <UTC_UNIX_SECONDS>`.
The option is off by default, and the cutoff is limited to 72 hours. The
JWKS failure response remains active after diagnostic collection stops.

The resource server fetches its configured HTTPS JWKS before first use and
refreshes the public-key snapshot ahead of its hard 300-second expiry. One
background task per verifier does this work. A fetch is bounded to six seconds;
failures retry no sooner than 30 seconds. Concurrent requests share one fetch.
Only a successfully fetched and validated snapshot renews the 300-second trust
period. A known key may be used until that period ends, even if a proactive
refresh fails. Unknown keys cause a bounded refresh.

When a request cannot be verified because JWKS is unavailable, `/mcp` returns
HTTP 503 with `Retry-After: 30` and no `WWW-Authenticate` challenge. No tool is
called. Missing, invalid, or expired bearer tokens still return HTTP 401 with
the normal SDK OAuth challenge. A valid JWKS that lacks a requested key is
treated as an invalid token, not a network failure.

Only 401 and JWKS-related 503 responses from `/mcp` are recorded. Their
`X-MCP-Diag-ID` is 16 random hex characters. The private
`/state/auth-401.sqlite` database contains only UTC Unix seconds, random ID,
status, a reason (`missing`, `expired`, `claims`, `jwks`, `other`), and a JWKS
failure detail (`dns_or_connect`, `timeout`, `tls`, `http_non200`,
`invalid_jwks`, `cooldown`, `other`). No identity, IP, request arguments,
headers, body, JWT, Telegram content, or token fingerprint is retained. The
previous 401-only table migrates in place without dropping its events.

Each write removes rows older than 24 hours and retains at most 256 rows.
The deployment operator must schedule deletion of this one database after
the collection cutoff, even if the container has stopped. Do not delete the
shared `/state` directory or its quota/checkpoint databases.

```sql
SELECT datetime(ts, 'unixepoch'), request_id, status, reason, detail
FROM auth_events
WHERE request_id = ?;
```

For a time-only report, use `WHERE ts BETWEEN ? AND ? ORDER BY ts`. If an error
has no ID and no matching row while collection is active, inspect the proxy
or client path; absence alone does not establish that no request was sent.
This feature makes no changes to OAuth grants, rotation, credentials, or the
existing Telegram session.
