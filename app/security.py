"""Cookie / JWT helpers and host-based URL derivation.

Two distinct token shapes share the same HS256 secret:
  - **session token** — what we put in the `rndexp_auth` cookie. 7-day TTL.
  - **OAuth state token** — short-lived (10m), holds the post-login `target`
    URL plus a CSRF nonce. Lives only in the redirect chain, never in storage.

Cookie scoping: we derive the cookie domain from the inbound request host so
the same image works in dev (`auth.rndexp.localhost` → `.rndexp.localhost`)
and prod (`auth.rndexp.art` → `.rndexp.art`). The derived domain MUST end
with one of `AUTH_ALLOWED_DOMAINS` or we fall back to a host-only cookie.
This is the one piece of code that determines who can read the user's
session, so it's worth being conservative.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import jwt
from fastapi import Request

from .config import settings


# --- session tokens ---------------------------------------------------------

@dataclass(frozen=True)
class SessionClaims:
    sub: str           # user id (string)
    email: str
    name: str
    picture: str
    roles: list[str]
    permissions: list[str]


def encode_session(*, sub: int, email: str, name: str, picture: str,
                   roles: list[str], permissions: list[str]) -> str:
    cfg = settings()
    import time
    now = int(time.time())
    payload = {
        "sub": str(sub),
        "email": email,
        "name": name,
        "picture": picture,
        "roles": roles,
        "permissions": permissions,
        "iat": now,
        "exp": now + cfg.cookie_ttl_seconds,
        "typ": "session",
    }
    return jwt.encode(payload, cfg.jwt_secret, algorithm="HS256")


def decode_session(token: str) -> SessionClaims | None:
    cfg = settings()
    try:
        data = jwt.decode(token, cfg.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if data.get("typ") != "session":
        return None
    return SessionClaims(
        sub=str(data.get("sub", "")),
        email=data.get("email", ""),
        name=data.get("name", ""),
        picture=data.get("picture", ""),
        roles=list(data.get("roles") or []),
        permissions=list(data.get("permissions") or []),
    )


# --- oauth state tokens -----------------------------------------------------

def encode_state(target: str | None, nonce: str) -> str:
    cfg = settings()
    import time
    now = int(time.time())
    return jwt.encode(
        {
            "target": target or "",
            "nonce": nonce,
            "iat": now,
            "exp": now + cfg.oauth_state_ttl_seconds,
            "typ": "state",
        },
        cfg.jwt_secret,
        algorithm="HS256",
    )


def decode_state(token: str) -> dict[str, Any] | None:
    cfg = settings()
    try:
        data = jwt.decode(token, cfg.jwt_secret, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    if data.get("typ") != "state":
        return None
    return data


# --- host / cookie helpers --------------------------------------------------

def request_host(request: Request) -> str:
    """The hostname (no port) seen by this request. Honors X-Forwarded-Host."""
    h = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    return h.split(",")[0].strip().split(":")[0].lower()


def request_scheme(request: Request) -> str:
    return (
        request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
        or request.url.scheme
        or "https"
    )


def base_url_for(request: Request) -> str:
    return f"{request_scheme(request)}://{request_host(request)}"


def cookie_domain_for(request: Request) -> str | None:
    """Compute the right Domain= attribute for our session cookie.

    Strategy: take the inbound host (e.g. `auth.rndexp.art`), strip the
    leftmost label, prepend a dot — that gives the parent domain. Then
    require the result to match one of AUTH_ALLOWED_DOMAINS. If it doesn't
    match (e.g. we were reached via raw IP, or someone forged Host: evil.com)
    return None and the caller will set a host-only cookie.
    """
    host = request_host(request)
    if not host or host in ("localhost", "127.0.0.1"):
        return None
    parts = host.split(".")
    if len(parts) < 2:
        return None
    parent = ".".join(parts[1:])
    allowed = settings().allowed_domains
    if parent in allowed:
        return f".{parent}"
    # Also accept exact match (host == allowed domain) — rare, but covers
    # the case where someone deploys at the apex.
    if host in allowed:
        return f".{host}"
    return None


def is_safe_target(target: str, request: Request) -> bool:
    """An open-redirect guard: only allow `target` URLs that point inside
    our own domain family.
    """
    if not target:
        return False
    # Allow site-relative targets (e.g. `/dashboard`).
    if target.startswith("/") and not target.startswith("//"):
        return True
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    allowed = settings().allowed_domains
    return any(host == d or host.endswith("." + d) for d in allowed)
