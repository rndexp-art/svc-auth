"""Runtime configuration. All knobs come from env vars (see ../.env.example).

We deliberately *don't* hard-code AUTH_BASE_URL / AUTH_COOKIE_DOMAIN — those
are derived per-request from the inbound Host header so the same image works
unchanged in dev and prod, and so a misconfigured DNS record can't poison the
service into emitting wrong-host redirects.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str | None = None, *, required: bool = False) -> str:
    val = os.environ.get(name, default)
    if required and not val:
        raise RuntimeError(f"Missing required env var: {name}")
    return val or ""


@dataclass(frozen=True)
class Settings:
    google_client_id: str = field(default_factory=lambda: _env("AUTH_GOOGLE_CLIENT_ID"))
    google_client_secret: str = field(default_factory=lambda: _env("AUTH_GOOGLE_CLIENT_SECRET"))
    jwt_secret: str = field(default_factory=lambda: _env("AUTH_JWT_SECRET"))
    db_path: str = field(default_factory=lambda: _env("AUTH_DB_PATH", "/data/auth.db"))
    initial_admin_email: str = field(default_factory=lambda: _env("AUTH_INITIAL_ADMIN_EMAIL", ""))
    # Comma-separated list of suffixes a cookie may be scoped to. We compute
    # the domain from the inbound host but cross-check against this allowlist
    # so a stray Host header can't widen the cookie to an arbitrary domain.
    allowed_domains: tuple[str, ...] = field(
        default_factory=lambda: tuple(
            d.strip().lstrip(".")
            for d in _env("AUTH_ALLOWED_DOMAINS", "rndexp.art,rndexp.localhost").split(",")
            if d.strip()
        )
    )
    cookie_name: str = "rndexp_auth"
    cookie_ttl_seconds: int = 60 * 60 * 24 * 7  # 7d
    oauth_state_ttl_seconds: int = 60 * 10  # 10m

    def google_configured(self) -> bool:
        return bool(self.google_client_id and self.google_client_secret)


_settings: Settings | None = None


def settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
        if not _settings.jwt_secret:
            raise RuntimeError(
                "AUTH_JWT_SECRET is required. Generate one with: "
                "python -c 'import secrets; print(secrets.token_urlsafe(48))'"
            )
    return _settings
