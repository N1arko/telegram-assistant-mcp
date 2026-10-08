# Temporary OAuth 401 diagnostics

Live mode can be started with `--auth-diagnostics-until-epoch <UTC_UNIX_SECONDS>`.
The option is off by default. It accepts a cutoff no more than 72 hours in the
future; an already-past cutoff keeps the service running with collection off.
Bootstrap mode does not accept the option.

Only HTTP 401 responses from `/mcp` are recorded. The response retains the
SDK's `WWW-Authenticate` challenge and gains `X-MCP-Diag-ID` (16 random hex
characters). The private `/state/auth-401.sqlite` database contains only UTC
Unix seconds, this random ID, status 401, and one category: `missing`,
`expired`, `claims`, `jwks`, or `other`. No identity, IP, method arguments,
headers, body, JWT, Telegram content, or token fingerprint is retained.

Each write removes rows older than 24 hours and retains at most 256 rows.
The deployment operator must schedule deletion of this one database after the
collection cutoff, even if the container has stopped. Do not delete the shared
`/state` directory or its quota/checkpoint databases. The request ID or a
precise UTC failure time can be used to query only these four columns:

```sql
SELECT datetime(ts, 'unixepoch'), request_id, status, reason
FROM auth_401
WHERE request_id = ?;
```

For a time-only report, use `WHERE ts BETWEEN ? AND ? ORDER BY ts`. If an error
has no ID and no matching row while collection is active, inspect the proxy
or client path; absence alone does not establish that no request was sent.
This feature makes no changes to bearer verification, OAuth grants, rotation,
or the existing Telegram session.
