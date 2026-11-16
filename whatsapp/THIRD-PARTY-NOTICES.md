# WhatsApp component notices

The Python resource server and helper scripts retain the repository's Apache-2.0
license. The new Go bridge source in `bridge/` is licensed GPL-3.0-only; see
`bridge/LICENSE`. This preserves the original Telegram project's licensing.

Direct Go dependencies:

| Module | Version | License |
|---|---|---|
| go.mau.fi/whatsmeow | v0.0.0-20260917111002-2e338d0ee73d | MPL-2.0 |
| github.com/mattn/go-sqlite3 | v1.14.52 | MIT |
| rsc.io/qr | v0.2.0 | BSD-3-Clause |
| google.golang.org/protobuf | v1.36.12 | BSD-3-Clause |

The transitive `go.mau.fi/libsignal v0.2.2` carries GPL-3.0. The bridge binary
links this module. The bridge's distribution should include the corresponding
source, this build helper and the pinned dependency sources, as well as notices;
do not describe the combined bridge as MIT-only or Apache-only. No public
distribution or publication is performed by this task.

`build.py` makes one local modification to whatsmeow's MPL-2.0 `send.go`: after a
disconnect response, return `ErrNotConnected` rather than resending the message
frame. The complete modified source, retaining its upstream copyright and MPL
notice, is generated in ignored `work/whatsapp-build/whatsmeow/send.go`; the
source hash, exact replacement and reproducible build are in `build.py`.

The MPL-2.0 extension `sdk/contact_lookup.go` is copied into the private SDK
source during the build. It reuses the pinned IsOnWhatsApp USync query while
preserving the explicit contact status for the bridge's strict tri-state
parser. The upstream `user.go` hash is checked too. Shared dependency caches
are unchanged; raw USync responses remain in memory and are never logged.

Upstream copyrights: whatsmeow — Tulir Asokan and contributors; libsignal —
its upstream contributors; go-sqlite3 — Yasuhiro Matsumoto and contributors;
qr — The Go Authors; protobuf — The Go Authors.
Exact notices and license texts for these modules are retained in `licenses/`.
Consult each pinned module for the complete file-level notices.

`verygoodplugins/whatsapp-mcp v0.7.0` was reviewed as a candidate. Its runtime
and scripts are not included or executed by this implementation. The new bridge
uses whatsmeow directly. That candidate's own MIT license does not describe the
licenses of all its dependencies.

Primary upstream licenses:
- https://github.com/tulir/whatsmeow/blob/2e338d0ee73d/LICENSE
- https://github.com/tulir/libsignal-protocol-go/blob/main/LICENSE
- https://github.com/mattn/go-sqlite3/blob/v1.14.52/LICENSE
- https://github.com/rsc/qr/blob/v0.2.0/LICENSE
- https://github.com/protocolbuffers/protobuf-go/blob/v1.36.12/LICENSE
