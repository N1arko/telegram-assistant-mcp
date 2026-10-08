"""OAuth resource-server verification using a configured Auth0 HTTPS JWKS endpoint."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from .auth_diagnostics import mark_auth_reason
from .security import Denied, private_file


def https_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        raise Denied("invalid_auth_config")
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise Denied("invalid_auth_config")
    return value


@dataclass(frozen=True)
class AuthConfig:
    issuer: str
    resource: str
    jwks_url: str
    allowed_subjects: tuple[str, ...] = ()
    algorithms: tuple[str, ...] = ("RS256",)

    def __post_init__(self):
        for url in (self.issuer, self.resource, self.jwks_url):
            https_url(url)
        if (not self.issuer.endswith("/") or
                self.jwks_url != self.issuer + ".well-known/jwks.json" or
                not isinstance(self.allowed_subjects, (tuple, list)) or
                not 1 <= len(self.allowed_subjects) <= 10 or
                any(not isinstance(s, str) or not 1 <= len(s) <= 2048 for s in self.allowed_subjects) or
                not isinstance(self.algorithms, (tuple, list)) or tuple(self.algorithms) != ("RS256",)):
            raise Denied("invalid_auth_config")

    @classmethod
    def load(cls, path):
        try:
            return cls(**json.loads(private_file(path)))
        except Exception:
            raise Denied("invalid_auth_config") from None


def validate_claims(data, config: AuthConfig, now):
    if not isinstance(data, dict) or data.get("iss") != config.issuer:
        return None
    subject = data.get("sub")
    if not isinstance(subject, str) or subject not in config.allowed_subjects:
        return None
    audience = data.get("aud")
    if not (audience == config.resource or (isinstance(audience, list) and
            all(isinstance(a, str) for a in audience) and config.resource in audience)):
        return None
    expiry = data.get("exp")
    if type(expiry) is not int or expiry <= now:
        return None
    if "nbf" in data and (type(data["nbf"]) is not int or data["nbf"] > now):
        return None
    scope = data.get("scope")
    if not isinstance(scope, str) or len(scope) > 4096:
        return None
    scopes = frozenset(scope.split())
    if "telegram:read" not in scopes:
        return None
    client = data.get("azp", subject)
    if not isinstance(client, str) or not 1 <= len(client) <= 2048:
        return None
    return client, scopes, expiry


class JWKSVerifier:
    """Only public keys are cached. JWTs are verified on every request.

    Expired keys never survive a failed refresh. Unknown kids trigger a bounded
    refresh; a successful refresh replaces the entire snapshot (including removals).
    No URL supplied in a token is ever used.
    """
    def __init__(self, config: AuthConfig, http=None, clock=time.time,
                 monotonic=time.monotonic, cache_seconds=300, refresh_seconds=30):
        import asyncio
        import httpx
        if not 1 <= cache_seconds <= 600 or not 1 <= refresh_seconds <= cache_seconds:
            raise ValueError("invalid_cache_config")
        self.config, self.clock, self.monotonic = config, clock, monotonic
        self.cache_seconds, self.refresh_seconds = cache_seconds, refresh_seconds
        self.keys, self.expires, self.retry_after = {}, 0, 0
        self.retry_reason = "jwks"
        self.lock = asyncio.Lock()
        self.http = http or httpx.AsyncClient(timeout=5, follow_redirects=False, trust_env=False,
                        limits=httpx.Limits(max_connections=4, max_keepalive_connections=2))

    async def _key(self, kid):
        async with self.lock:
            now = self.monotonic()
            if now < self.expires and kid in self.keys:
                return self.keys[kid], None
            if now < self.retry_after:
                return None, self.retry_reason
            self.retry_after = now + self.refresh_seconds
            self.retry_reason = "jwks"
            try:
                import jwt
                async with self.http.stream("GET", self.config.jwks_url,
                        headers={"Accept": "application/json"}) as response:
                    if response.status_code != 200:
                        return None, "jwks"
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 65536:
                            return None, "jwks"
                document = json.loads(body)
                entries = document.get("keys") if isinstance(document, dict) else None
                if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
                    return None, "jwks"
                keys = {}
                for entry in entries:
                    if not isinstance(entry, dict):
                        return None, "jwks"
                    ident = entry.get("kid")
                    if not isinstance(ident, str) or not 1 <= len(ident) <= 256 or ident in keys:
                        return None, "jwks"
                    if (entry.get("kty") != "RSA" or entry.get("use", "sig") != "sig" or
                            entry.get("alg", "RS256") != "RS256" or
                            entry.get("key_ops", ["verify"]) != ["verify"] or "d" in entry):
                        return None, "jwks"
                    key = jwt.algorithms.RSAAlgorithm.from_jwk(entry)
                    if key.key_size < 2048:
                        return None, "jwks"
                    keys[ident] = key
                self.keys, self.expires = keys, self.monotonic() + self.cache_seconds
                self.retry_reason = "claims"
                return keys.get(kid), "claims" if kid not in keys else None
            except Exception:
                return None, "jwks"

    async def verify_token(self, token):
        from mcp.server.auth.provider import AccessToken
        if not isinstance(token, str) or not 1 <= len(token) <= 8192:
            mark_auth_reason("claims")
            return None
        try:
            import jwt
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            if (header.get("alg") not in self.config.algorithms or
                    not isinstance(kid, str) or not 1 <= len(kid) <= 256 or
                    any(name in header for name in ("crit", "b64", "jku", "x5u", "jwk"))):
                mark_auth_reason("claims")
                return None
            key, key_failure = await self._key(kid)
            if key is None:
                mark_auth_reason(key_failure)
                return None
            data = jwt.decode(token, key, algorithms=list(self.config.algorithms),
                options={"verify_exp": False, "verify_nbf": False, "verify_iat": False,
                         "verify_aud": False, "verify_iss": False})
            now = self.clock()
            if type(data.get("exp")) is int and data["exp"] <= now:
                mark_auth_reason("expired")
                return None
            result = validate_claims(data, self.config, now)
            if result is None:
                mark_auth_reason("claims")
                return None
            client, scopes, expires = result
            mark_auth_reason("other")  # Only used if a later middleware still returns 401.
            return AccessToken(token=token, client_id=client, scopes=sorted(scopes),
                               expires_at=expires, resource=self.config.resource)
        except Exception:
            mark_auth_reason("claims")
            return None

    async def close(self):
        await self.http.aclose()
