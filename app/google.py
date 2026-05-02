"""Thin wrapper around Authlib's Google OAuth client.

We don't keep server-side session state — the OAuth `state` parameter
carries our own JWT (see security.encode_state) that round-trips the
post-login `target` URL plus a CSRF nonce. Authlib's higher-level
`OAuth.register` integrations want a session backend; using the lower-level
`OAuth2Client` keeps things stateless.
"""
from __future__ import annotations

import secrets
from urllib.parse import urlencode

import httpx
from authlib.jose import JsonWebKey, JsonWebToken

from .config import settings


GOOGLE_AUTHORIZE = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GOOGLE_JWKS = "https://www.googleapis.com/oauth2/v3/certs"

_jwks_cache: JsonWebKey | None = None


def authorize_url(*, redirect_uri: str, state: str, scopes: tuple[str, ...] = ("openid", "email", "profile")) -> str:
    params = {
        "client_id": settings().google_client_id,
        "response_type": "code",
        "scope": " ".join(scopes),
        "redirect_uri": redirect_uri,
        "state": state,
        "access_type": "online",
        "prompt": "select_account",
    }
    return f"{GOOGLE_AUTHORIZE}?{urlencode(params)}"


def new_nonce() -> str:
    return secrets.token_urlsafe(24)


def exchange_code(*, code: str, redirect_uri: str) -> dict:
    """POST to Google's token endpoint; returns the JSON token response."""
    cfg = settings()
    data = {
        "code": code,
        "client_id": cfg.google_client_id,
        "client_secret": cfg.google_client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    with httpx.Client(timeout=10) as c:
        r = c.post(GOOGLE_TOKEN, data=data)
    r.raise_for_status()
    return r.json()


def fetch_jwks() -> JsonWebKey:
    """Fetch Google's JWKS and parse it for ID-token verification.

    Cached for the lifetime of the process — a longer-running deployment
    should ideally refresh on `kid` miss, but Google rotates infrequently
    and the OAuth flow itself is rare enough that a redeploy on rotation
    is acceptable.
    """
    global _jwks_cache
    if _jwks_cache is not None:
        return _jwks_cache
    with httpx.Client(timeout=10) as c:
        r = c.get(GOOGLE_JWKS)
    r.raise_for_status()
    _jwks_cache = JsonWebKey.import_key_set(r.json())
    return _jwks_cache


def verify_id_token(id_token: str) -> dict:
    """Verify a Google ID token's signature, audience, issuer and expiry.

    Returns the decoded claims (sub, email, email_verified, name, picture,
    iss, aud, exp, ...). Raises on any failure.
    """
    cfg = settings()
    jwt_codec = JsonWebToken(["RS256"])
    claims = jwt_codec.decode(
        id_token,
        key=fetch_jwks(),
        claims_options={
            "iss": {"essential": True, "values": ["https://accounts.google.com", "accounts.google.com"]},
            "aud": {"essential": True, "value": cfg.google_client_id},
        },
    )
    claims.validate()  # checks exp / nbf / iat
    return dict(claims)
