"""Routes that bridge the auth service to the telegram-bot service.

Two outward-facing routes (browser-driven):

  GET  /link/telegram?code=…       Logged-in user opens this from the bot's
                                   /start reply. We POST the code to the bot
                                   to learn which Telegram account it
                                   represents, then bind it to the current
                                   auth user.

  POST /link/telegram/unlink       Drop telegram_id from the current user.

One inward-facing route (called by the bot, gated by AUTH_INTERNAL_TOKEN):

  GET  /internal/telegram/users/{telegram_id}
                                   Returns `{user_id, email, name}` for the
                                   bound user, or 404 if no binding.

Why the inward route lives here and not in routes_api: routes_api gates
everything on a session cookie + admin role. Service-to-service calls have
neither — they present a shared secret instead.
"""
from __future__ import annotations

import hmac
import logging
import os
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db, security
from .config import settings


log = logging.getLogger(__name__)

router = APIRouter()
_templates: Jinja2Templates | None = None


def init(templates: Jinja2Templates) -> None:
    global _templates
    _templates = templates


def _t() -> Jinja2Templates:
    if _templates is None:
        raise RuntimeError("routes_telegram.init(templates) must be called at startup")
    return _templates


# --- env knobs --------------------------------------------------------------

def _bot_internal_url() -> str:
    return os.environ.get("TELEGRAM_BOT_INTERNAL_URL", "http://telegram-bot:8004").rstrip("/")


def _internal_token() -> str:
    tok = os.environ.get("AUTH_INTERNAL_TOKEN", "")
    if not tok:
        raise HTTPException(503, "AUTH_INTERNAL_TOKEN not configured on auth service")
    return tok


# --- DI ---------------------------------------------------------------------

def _db_session():
    s = db.session()
    try:
        yield s
    finally:
        s.close()


def _current_claims(request: Request) -> security.SessionClaims | None:
    tok = request.cookies.get(settings().cookie_name)
    if not tok:
        return None
    return security.decode_session(tok)


# --- /link/telegram ---------------------------------------------------------

@router.get("/link/telegram", response_class=HTMLResponse)
def link_telegram(
    request: Request,
    code: str = "",
    s: Session = Depends(_db_session),
):
    """User clicks the link the bot DMed them.

    If they're not signed in yet, bounce through the login page and come back.
    Otherwise, redeem the code with the bot service and persist `telegram_id`
    on their user row.
    """
    if not code:
        return _t().TemplateResponse(
            request,
            "telegram_link_result.html",
            {"ok": False, "error": "Missing code parameter."},
            status_code=400,
        )

    claims = _current_claims(request)
    if claims is None:
        # Bounce to login, asking it to send the user back here after.
        from urllib.parse import urlencode
        target = f"{security.base_url_for(request)}/link/telegram?{urlencode({'code': code})}"
        return RedirectResponse(
            url=f"/?{urlencode({'target': target})}",
            status_code=302,
        )

    try:
        auth_user_id = int(claims.sub)
    except (TypeError, ValueError):
        raise HTTPException(401, "invalid session")

    # Call the bot's internal API. If the bot is unreachable we don't want
    # to mask the error — show it to the user so they can retry rather than
    # silently failing.
    try:
        r = httpx.post(
            f"{_bot_internal_url()}/internal/link-codes/{code}/redeem",
            json={"auth_user_id": auth_user_id},
            headers={"X-Internal-Token": _internal_token()},
            timeout=httpx.Timeout(connect=2.0, read=5.0, write=5.0, pool=2.0),
        )
    except httpx.HTTPError as e:
        log.exception("bot redeem call failed")
        return _t().TemplateResponse(
            request,
            "telegram_link_result.html",
            {"ok": False, "error": f"Could not reach the Telegram bot service: {e}"},
            status_code=502,
        )

    if r.status_code == 410:
        return _t().TemplateResponse(
            request,
            "telegram_link_result.html",
            {"ok": False, "error": "This link is expired or already used. "
                                   "Send /start to the bot again to get a fresh one."},
            status_code=410,
        )
    if r.status_code != 200:
        return _t().TemplateResponse(
            request,
            "telegram_link_result.html",
            {"ok": False, "error": f"Bot rejected the code (status {r.status_code})."},
            status_code=502,
        )

    try:
        data = r.json()
        telegram_id = int(data.get("telegram_id") or 0)
    except (ValueError, TypeError):
        return _t().TemplateResponse(
            request,
            "telegram_link_result.html",
            {"ok": False, "error": "Bot returned a malformed response."},
            status_code=502,
        )
    if telegram_id <= 0:
        return _t().TemplateResponse(
            request,
            "telegram_link_result.html",
            {"ok": False, "error": "Bot did not return a Telegram id."},
            status_code=502,
        )

    user = s.get(db.User, auth_user_id)
    if user is None:
        raise HTTPException(404, "current user not found")

    # Reject if a different user already has this telegram_id bound. The
    # partial unique index would also reject the commit, but giving a clean
    # 409 here is friendlier than letting the IntegrityError bubble.
    other = s.scalar(
        select(db.User).where(db.User.telegram_id == telegram_id, db.User.id != user.id)
    )
    if other is not None:
        return _t().TemplateResponse(
            request,
            "telegram_link_result.html",
            {"ok": False, "error": "This Telegram account is already linked to a different rndexp.art account. "
                                   "Unlink it from the other account first."},
            status_code=409,
        )

    user.telegram_id = telegram_id
    s.commit()

    username = data.get("username") or ""
    first_name = data.get("first_name") or ""
    return _t().TemplateResponse(
        request,
        "telegram_link_result.html",
        {"ok": True, "username": username, "first_name": first_name, "email": user.email},
    )


@router.post("/link/telegram/unlink")
def unlink_telegram(
    request: Request,
    s: Session = Depends(_db_session),
):
    claims = _current_claims(request)
    if claims is None:
        raise HTTPException(401, "not authenticated")
    try:
        auth_user_id = int(claims.sub)
    except (TypeError, ValueError):
        raise HTTPException(401, "invalid session")
    user = s.get(db.User, auth_user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    user.telegram_id = None
    s.commit()
    return RedirectResponse(url="/me", status_code=303)


# --- /internal/telegram (called by the bot) --------------------------------

def _require_internal_token(x_internal_token: str | None) -> None:
    expected = _internal_token()
    if not x_internal_token or not hmac.compare_digest(x_internal_token, expected):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="bad internal token")


@router.get("/internal/telegram/users/{telegram_id}")
def internal_lookup(
    telegram_id: int,
    x_internal_token: Annotated[str | None, Header()] = None,
    s: Session = Depends(_db_session),
) -> dict:
    """Bot → auth lookup. Returns 404 if no user has bound this telegram_id."""
    _require_internal_token(x_internal_token)
    user = s.scalar(select(db.User).where(db.User.telegram_id == telegram_id))
    if user is None:
        raise HTTPException(404, "no user bound to this telegram_id")
    return {
        "user_id": user.id,
        "email": user.email,
        "name": user.name,
    }
