"""Password hashing + one-time token helpers.

Passwords are hashed with bcrypt (cost=12). Tokens (invite + reset) are
generated with `secrets.token_urlsafe(32)` and stored as their sha256 hex
digest, so the plaintext value only ever lives in the URL emailed to the
user. Comparing token hashes uses `hmac.compare_digest` to avoid timing
side channels.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone

import bcrypt


# --- passwords --------------------------------------------------------------

# bcrypt's salt is part of the hash, so verify() doesn't need a separate one.
# 12 rounds ≈ ~250ms on a 2024 laptop — comfortable middle ground for a
# small admin login.
_BCRYPT_ROUNDS = 12

# bcrypt accepts at most 72 bytes; longer passwords are silently truncated.
# We pre-hash with sha256 so users don't lose entropy past that limit.
_PRE_HASH_PREFIX = b"rndexp_auth_v1\x00"


def _normalize(password: str) -> bytes:
    digest = hashlib.sha256(_PRE_HASH_PREFIX + password.encode("utf-8")).digest()
    # Use the hex form so the bytes are bcrypt-safe (no embedded NULs etc.).
    return digest.hex().encode("ascii")


MIN_PASSWORD_LENGTH = 10


class WeakPasswordError(ValueError):
    pass


def validate_password(password: str) -> None:
    """Raise WeakPasswordError if `password` is too weak.

    The bar is intentionally low — admins set their own passwords, not
    public end users — but we still block trivially-short ones and the
    classic `password`/`12345678`/etc.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    if password.lower() in {"password12", "password123", "qwertyuiop", "1234567890"}:
        raise WeakPasswordError("that password is in the common-password blocklist")


def hash_password(password: str) -> str:
    validate_password(password)
    salt = bcrypt.gensalt(rounds=_BCRYPT_ROUNDS)
    return bcrypt.hashpw(_normalize(password), salt).decode("ascii")


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(_normalize(password), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


# --- one-time tokens --------------------------------------------------------

def new_token() -> tuple[str, str]:
    """Returns (plaintext, hash). Store the hash, mail the plaintext."""
    plaintext = secrets.token_urlsafe(32)
    return plaintext, hash_token(plaintext)


def hash_token(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def is_expired(expires_at: datetime) -> bool:
    """Tokens carry timezone-aware expiry; tolerate naive ones for safety."""
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    return datetime.now(tz=timezone.utc) >= expires_at
