"""JSON CRUD API for the dashboard's Users tab.

All endpoints require the `auth.admin` permission, enforced by the same
session-cookie check the HTML /admin page uses.

Last-admin guard: deleting an admin or revoking the `admin` role is rejected
with 409 if it would leave the system with zero admins.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db, mail, passwords, security


router = APIRouter(prefix="/api")


# --- DI helpers (mirror main.py to avoid circular imports) -----------------

def _db_session():
    s = db.session()
    try:
        yield s
    finally:
        s.close()


def _current_claims(request: Request) -> security.SessionClaims:
    from .config import settings
    tok = request.cookies.get(settings().cookie_name)
    if not tok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated")
    claims = security.decode_session(tok)
    if claims is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated")
    return claims


def _require_admin(request: Request) -> security.SessionClaims:
    claims = _current_claims(request)
    if "auth.admin" not in claims.permissions:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin permission required")
    return claims


# --- payloads ---------------------------------------------------------------

class UserOut(BaseModel):
    id: int
    email: str
    name: str
    picture_url: str
    has_password: bool
    has_google: bool
    has_telegram: bool
    roles: list[str]
    permissions: list[str]
    created_at: datetime
    last_login_at: datetime


class InviteIn(BaseModel):
    email: EmailStr
    roles: list[str] = Field(default_factory=list)


class InviteOut(BaseModel):
    email: str
    invite_url: str
    expires_at: datetime
    email_sent: bool
    email_reason: str = ""


class RoleIn(BaseModel):
    role_slug: str


def _user_to_out(u: db.User) -> UserOut:
    return UserOut(
        id=u.id,
        email=u.email,
        name=u.name,
        picture_url=u.picture_url,
        has_password=u.has_password(),
        has_google=u.has_google(),
        has_telegram=u.has_telegram(),
        roles=u.role_slugs(),
        permissions=u.permission_slugs(),
        created_at=u.created_at,
        last_login_at=u.last_login_at,
    )


# --- routes ----------------------------------------------------------------

@router.get("/users", response_model=list[UserOut])
def list_users(
    _: Annotated[security.SessionClaims, Depends(_require_admin)],
    s: Session = Depends(_db_session),
):
    users = list(s.scalars(select(db.User).order_by(db.User.email)).all())
    return [_user_to_out(u) for u in users]


@router.get("/users/me", response_model=UserOut)
def my_user(
    me: Annotated[security.SessionClaims, Depends(_require_admin)],
    s: Session = Depends(_db_session),
):
    """Convenience for the dashboard: 'who am I, in DB form'. Same admin
    gate as the rest of /api so we don't accidentally expose this to non-admins.
    """
    user = s.scalar(select(db.User).where(db.User.id == int(me.sub)))
    if user is None:
        raise HTTPException(404, "user not found")
    return _user_to_out(user)


@router.get("/roles", response_model=list[str])
def list_role_slugs(
    _: Annotated[security.SessionClaims, Depends(_require_admin)],
    s: Session = Depends(_db_session),
):
    return [r.slug for r in s.scalars(select(db.Role).order_by(db.Role.slug)).all()]


@router.post("/users/invite", response_model=InviteOut, status_code=201)
def invite_user(
    payload: InviteIn,
    me: Annotated[security.SessionClaims, Depends(_require_admin)],
    request: Request,
    s: Session = Depends(_db_session),
):
    email = payload.email.lower()

    # Validate requested roles up front so we don't email a bad invite.
    if payload.roles:
        existing = {
            r.slug for r in s.scalars(select(db.Role).where(db.Role.slug.in_(payload.roles))).all()
        }
        unknown = [r for r in payload.roles if r not in existing]
        if unknown:
            raise HTTPException(400, f"unknown role(s): {','.join(unknown)}")

    # Re-issuing an invite for a not-yet-redeemed email is fine (we keep the
    # old token valid until expiry; the new link arrives in a fresh email).
    plaintext, hash_ = passwords.new_token()
    inv = db.InviteToken(
        email=email,
        token_hash=hash_,
        created_by_user_id=int(me.sub),
        expires_at=datetime.now(tz=timezone.utc) + db.INVITE_TOKEN_TTL,
        granted_role_slugs=",".join(payload.roles),
    )
    s.add(inv)
    s.commit()

    url = f"{security.base_url_for(request)}/invite/{plaintext}"
    body = (
        f"Hi,\n\nYou've been invited to rndexp.art. To set your password and "
        f"sign in, open this link within "
        f"{int(db.INVITE_TOKEN_TTL.total_seconds() // 3600)} hours:\n\n{url}\n\n"
        f"If you didn't expect this invite, you can ignore this email."
    )
    result = mail.send(to=email, subject="You're invited to rndexp.art", body_text=body)

    return InviteOut(
        email=email,
        invite_url=url,
        expires_at=inv.expires_at,
        email_sent=result.sent,
        email_reason=result.reason,
    )


@router.post("/users/{user_id}/reset-password", response_model=InviteOut, status_code=201)
def admin_trigger_reset(
    user_id: int,
    me: Annotated[security.SessionClaims, Depends(_require_admin)],
    request: Request,
    s: Session = Depends(_db_session),
):
    """Admin-initiated password reset. Returns the same shape as invite so
    the dashboard UI can show the operator the link if SMTP is unconfigured.
    """
    user = s.get(db.User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    plaintext, hash_ = passwords.new_token()
    prt = db.PasswordResetToken(
        user_id=user.id,
        token_hash=hash_,
        expires_at=datetime.now(tz=timezone.utc) + db.PASSWORD_RESET_TTL,
    )
    s.add(prt)
    s.commit()
    url = f"{security.base_url_for(request)}/reset-password/{plaintext}"
    body = (
        f"Hi,\n\nAn administrator triggered a password reset for {user.email}. "
        f"Open this link within "
        f"{int(db.PASSWORD_RESET_TTL.total_seconds() // 60)} minutes to choose a "
        f"new password:\n\n{url}"
    )
    result = mail.send(to=user.email, subject="rndexp.art password reset", body_text=body)
    return InviteOut(
        email=user.email,
        invite_url=url,
        expires_at=prt.expires_at,
        email_sent=result.sent,
        email_reason=result.reason,
    )


@router.delete("/users/{user_id}", status_code=204)
def delete_user(
    user_id: int,
    me: Annotated[security.SessionClaims, Depends(_require_admin)],
    s: Session = Depends(_db_session),
):
    user = s.get(db.User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    if db.is_last_admin(s, user):
        raise HTTPException(409, "cannot delete the last user holding the `admin` role")
    s.delete(user)
    s.commit()
    return None  # 204


@router.post("/users/{user_id}/roles", response_model=UserOut)
def grant_role(
    user_id: int,
    payload: RoleIn,
    _: Annotated[security.SessionClaims, Depends(_require_admin)],
    s: Session = Depends(_db_session),
):
    user = s.get(db.User, user_id)
    if user is None:
        raise HTTPException(404, "user not found")
    role = s.scalar(select(db.Role).where(db.Role.slug == payload.role_slug.strip().lower()))
    if role is None:
        raise HTTPException(404, "role not found")
    if role not in user.roles:
        user.roles.append(role)
        s.commit()
    return _user_to_out(user)


@router.delete("/users/{user_id}/roles/{role_slug}", response_model=UserOut)
def revoke_role(
    user_id: int,
    role_slug: str,
    _: Annotated[security.SessionClaims, Depends(_require_admin)],
    s: Session = Depends(_db_session),
):
    user = s.get(db.User, user_id)
    role = s.scalar(select(db.Role).where(db.Role.slug == role_slug.strip().lower()))
    if user is None or role is None:
        raise HTTPException(404, "user or role not found")
    if role.slug == db.ADMIN_ROLE_SLUG and db.is_last_admin(s, user):
        raise HTTPException(409, "cannot revoke `admin` from the last admin")
    if role in user.roles:
        user.roles.remove(role)
        s.commit()
    return _user_to_out(user)
