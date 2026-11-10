# Unified Telegram MCP releases

The release branch includes public-channel reads/listing, exact-post text pagination,
the deployed metadata-only diagnostic hooks, and document-text pagination.
Runtime credentials, policy, Telegram sessions, and mutable state remain external.
Do not include local WhatsApp files or unrelated workspace changes in this release.

## Build and verify

1. Record the running container's image ID, effective Compose configuration, source
   hashes, command, mounts, health check, network aliases, and security options.
   Copy source code only when reconciling an existing deployed version. Never copy
   runtime credentials, session data, or message contents into the repository.
2. Pin the current image under a new local baseline tag and verify its image ID.
   Build `deploy/Dockerfile.release` using that tag as `BASE_IMAGE` and the exact
   source commit as `RELEASE_COMMIT`, with `--pull=false --network=none`.
   The build checks every retained dependency against `requirements.lock`, then
   installs the complete source package without downloading dependencies.
3. Run the entire mock suite in the resulting Linux image, with networking disabled,
   no runtime/session mounts, a read-only source/test mount, and a temporary writable
   directory. Allocate a PTY for the terminal-input tests. These tests must not log
   into Telegram or send/read real messages.
4. Verify the image's imported package path, version, tool schemas, and source hashes.
   Check `read_document` continuation parameters and preserve all existing tools.

## Deploy and roll back

Generate one effective Compose file from the deployed configuration. Preserve all
service settings, command flags, mounts, aliases, resource limits, logging, and
security options. Only replace the image and its build definition. Keep the prior
configuration and image unchanged in a release-specific rollback directory.

Use the existing Compose project/service and `up -d --no-deps --no-build assistant`.
Never run a second live client on the same Telegram session. Do not change ingress,
OAuth grants, policy, credentials, or unrelated services.

After replacement, check container health, exact image/revision, source hashes,
public OAuth metadata, and the unauthenticated MCP 401 response. Inspect registered
tool schemas without connecting another Telegram client. Authenticated acceptance
must use the existing connector and only the exact user-authorized document.

If startup, health, source verification, or access checks fail, run the same Compose
project/service using the saved prior effective configuration and image. Confirm
old-image health and the metadata/401 checks after rollback. Keep the previous image
until the updated connector behavior is verified. Do not prune unrelated images.
