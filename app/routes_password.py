"""HTML routes for password-based login, invite redemption, and reset.

These coexist with the existing Google OAuth flow on the same login page —
the user picks Google or email+password. Invite and reset URLs are emailed
to the user and consumed by GET → form → POST here.

The password and reset-token flows reuse the same session cookie helpers as
the Google flow (defined in main.py); the cookie is re-issued on each
successful auth.
"""
from __future__ import annotations

from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db, mail, passwords, security
from .config import settings


router = APIRouter()
_templates: Jinja2Templates | None = None


def init(templates: Jinja2Templates) -> None:
    """Wire the shared Jinja Templates instance from main.py."""
    global _templates
    _templates = templates


def _t() -> Jinja2Templates:
    if _templates is None:
        raise RuntimeError("routes_password.init(templates) must be called at startup")
    return _templates


# --- DI helpers (shadow the ones in main.py to avoid a circular import) ----

def _db_session():
    s = db.session()
    try:
        yield s
    finally:
        s.close()


# --- callbacks main.py exposes (set during init) ---------------------------

_set_session_cookie = None
_clear_session_cookie = None


def configure_cookies(*, set_cookie, clear_cookie) -> None:
    """main.py wires these in so we don't duplicate the cookie-domain logic."""
    global _set_session_cookie, _clear_session_cookie
    _set_session_cookie = set_cookie
    _clear_session_cookie = clear_cookie


def _login(response: Response, request: Request, user: db.User) -> Response:
    """Mint a fresh session cookie for `user` and stamp it on `response`."""
    token = security.encode_session(
        sub=user.id,
        email=user.email,
        name=user.name,
        picture=user.picture_url,
        roles=user.role_slugs(),
        permissions=user.permission_slugs(),
    )
    _set_session_cookie(response, token, request)
    return response


# --- /login (password) ------------------------------------------------------

@router.post("/login")
def login_with_password(
    request: Request,
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    target: Annotated[str, Form()] = "",
    s: Session = Depends(_db_session),
):
    email = email.strip().lower()
    user = s.scalar(select(db.User).where(db.User.email == email))
    # Constant-time-ish: always run a verify even on no-such-user so the
    # response time doesn't reveal whether an email exists in the DB.
    if user is None:
        passwords.verify_password(password, "$2b$12$" + "x" * 53)  # always-fails dummy
        return _t().TemplateResponse(
            request,
            "login.html",
            {
                "target": target if security.is_safe_target(target, request) else "",
                "start_url": "/auth/google/start",
                "google_configured": settings().google_configured(),
                "error": "Invalid email or password.",
                "email": email,
            },
            status_code=401,
        )
    if not passwords.verify_password(password, user.password_hash):
        return _t().TemplateResponse(
            request,
            "login.html",
            {
                "target": target if security.is_safe_target(target, request) else "",
                "start_url": "/auth/google/start",
                "google_configured": settings().google_configured(),
                "error": "Invalid email or password.",
                "email": email,
            },
            status_code=401,
        )

    from datetime import datetime, timezone
    user.last_login_at = datetime.now(tz=timezone.utc)
    s.commit()

    safe_target = target if security.is_safe_target(target, request) else "/me"
    resp = RedirectResponse(url=safe_target, status_code=302)
    return _login(resp, request, user)


# --- /invite/{token} --------------------------------------------------------

def _find_invite(s: Session, token: str) -> db.InviteToken | None:
    """Look up an invite by hashed token, ensure it's still claimable."""
    if not token:
        return None
    inv = s.scalar(select(db.InviteToken).where(db.InviteToken.token_hash == passwords.hash_token(token)))
    if inv is None:
        return None
    if inv.redeemed_at is not None:
        return None
    if passwords.is_expired(inv.expires_at):
        return None
    return inv


@router.get("/invite/{token}", response_class=HTMLResponse)
def invite_form(token: str, request: Request, s: Session = Depends(_db_session)):
    inv = _find_invite(s, token)
    if inv is None:
        return _t().TemplateResponse(
            request,
            "token_invalid.html",
            {"kind": "invite"},
            status_code=410,
        )
    return _t().TemplateResponse(
        request,
        "set_password.html",
        {"token": token, "email": inv.email, "kind": "invite"},
    )


@router.post("/invite/{token}")
def invite_redeem(
    token: str,
    request: Request,
    password: Annotated[str, Form()],
    password_confirm: Annotated[str, Form()],
    s: Session = Depends(_db_session),
):
    inv = _find_invite(s, token)
    if inv is None:
        return _t().TemplateResponse(
            request,
            "token_invalid.html",
            {"kind": "invite"},
            status_code=410,
        )

    if password != password_confirm:
        return _t().TemplateResponse(
            request,
            "set_password.html",
            {"token": token, "email": inv.email, "kind": "invite",
             "error": "Passwords do not match."},
            status_code=400,
        )
    try:
        pw_hash = passwords.hash_password(password)
    except passwords.WeakPasswordError as e:
        return _t().TemplateResponse(
            request,
            "set_password.html",
            {"token": token, "email": inv.email, "kind": "invite", "error": str(e)},
            status_code=400,
        )

    user = s.scalar(select(db.User).where(db.User.email == inv.email.lower()))
    is_new = user is None
    if is_new:
        user = db.User(email=inv.email.lower(), name="", picture_url="", password_hash=pw_hash)
        s.add(user)
        s.flush()
    else:
        user.password_hash = pw_hash

    # Always grant the default `user` role; grant any explicit roles the
    # inviter requested.
    role_slugs = ["user"]
    if inv.granted_role_slugs:
        role_slugs.extend(slug.strip() for slug in inv.granted_role_slugs.split(",") if slug.strip())
    db._grant_roles(s, user, role_slugs)

    from datetime import datetime, timezone
    inv.redeemed_at = datetime.now(tz=timezone.utc)
    user.last_login_at = inv.redeemed_at
    s.commit()

    resp = RedirectResponse(url="/me", status_code=302)
    return _login(resp, request, user)


# --- /forgot-password + /reset-password/{token} -----------------------------

@router.get("/forgot-password", response_class=HTMLResponse)
def forgot_password_form(request: Request):
    return _t().TemplateResponse(request, "forgot_password.html", {})


@router.post("/forgot-password", response_class=HTMLResponse)
def forgot_password_submit(
    request: Request,
    email: Annotated[str, Form()],
    s: Session = Depends(_db_session),
):
    """Always render the same "we sent a link if that account exists" page,
    regardless of whether the email is registered, to avoid account-existence
    enumeration.
    """
    email = email.strip().lower()
    user = s.scalar(select(db.User).where(db.User.email == email))

    if user is not None:
        from datetime import datetime, timezone
        plaintext, hash_ = passwords.new_token()
        prt = db.PasswordResetToken(
            user_id=user.id,
            token_hash=hash_,
            expires_at=datetime.now(tz=timezone.utc) + db.PASSWORD_RESET_TTL,
        )
        s.add(prt)
        s.commit()

        url = f"{security.base_url_for(request)}/reset-password/{plaintext}"
        mail.send(
            to=email,
            subject="Reset your rndexp.art password",
            body_text=(
                f"Hi,\n\nA password reset was requested for {email}. "
                f"To choose a new password, open this link within "
                f"{int(db.PASSWORD_RESET_TTL.total_seconds() // 60)} minutes:\n\n{url}\n\n"
                f"If you didn't request this, you can ignore this email."
            ),
        )

    return _t().TemplateResponse(request, "forgot_password_sent.html", {"email": email})


def _find_reset(s: Session, token: str) -> db.PasswordResetToken | None:
    if not token:
        return None
    prt = s.scalar(
        select(db.PasswordResetToken).where(db.PasswordResetToken.token_hash == passwords.hash_token(token))
    )
    if prt is None or prt.used_at is not None or passwords.is_expired(prt.expires_at):
        return None
    return prt


@router.get("/reset-password/{token}", response_class=HTMLResponse)
def reset_password_form(token: str, request: Request, s: Session = Depends(_db_session)):
    prt = _find_reset(s, token)
    if prt is None:
        return _t().TemplateResponse(request, "token_invalid.html", {"kind": "reset"}, status_code=410)
    user = s.get(db.User, prt.user_id)
    return _t().TemplateResponse(
        request,
        "set_password.html",
        {"token": token, "email": user.email if user else "", "kind": "reset"},
    )


@router.post("/reset-password/{token}")
def reset_password_submit(
    token: str,
    request: Request,
    password: Annotated[str, Form()],
    password_confirm: Annotated[str, Form()],
    s: Session = Depends(_db_session),
):
    prt = _find_reset(s, token)
    if prt is None:
        return _t().TemplateResponse(request, "token_invalid.html", {"kind": "reset"}, status_code=410)
    user = s.get(db.User, prt.user_id)
    if user is None:
        return _t().TemplateResponse(request, "token_invalid.html", {"kind": "reset"}, status_code=410)

    if password != password_confirm:
        return _t().TemplateResponse(
            request,
            "set_password.html",
            {"token": token, "email": user.email, "kind": "reset",
             "error": "Passwords do not match."},
            status_code=400,
        )
    try:
        user.password_hash = passwords.hash_password(password)
    except passwords.WeakPasswordError as e:
        return _t().TemplateResponse(
            request,
            "set_password.html",
            {"token": token, "email": user.email, "kind": "reset", "error": str(e)},
            status_code=400,
        )

    from datetime import datetime, timezone
    prt.used_at = datetime.now(tz=timezone.utc)
    user.last_login_at = prt.used_at
    s.commit()

    resp = RedirectResponse(url="/me", status_code=302)
    return _login(resp, request, user)
