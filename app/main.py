"""FastAPI app for the rndexp.art auth service.

Routes:
  GET  /                          login page (?target=URL)
  GET  /auth/google/start         begin Google OAuth (?target=URL)
  GET  /auth/google/callback      OAuth callback — sets cookie + 302 to target
  GET  /me                        current user JSON (or 401)
  GET  /verify                    forward-auth probe (200 + headers, or 401)
  POST /logout                    clear cookie (?target=URL to bounce)
  GET  /admin                     admin UI (requires `auth.admin` permission)
  POST /admin/roles               create role
  POST /admin/permissions         create permission
  POST /admin/users/{id}/roles    grant role to user
  POST /admin/users/{id}/roles/{slug}/revoke
                                  revoke role from user
  POST /admin/roles/{slug}/permissions
                                  attach a permission to a role
  GET  /healthz                   liveness
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import db, google, routes_api, routes_password, routes_telegram, security
from .config import settings


TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


@asynccontextmanager
async def _lifespan(app: FastAPI):
    db.init_engine()
    yield


app = FastAPI(title="rndexp-art auth", docs_url=None, redoc_url=None, lifespan=_lifespan)


# --- DI helpers -------------------------------------------------------------

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


def _require_user(request: Request) -> security.SessionClaims:
    claims = _current_claims(request)
    if claims is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="not authenticated")
    return claims


def _require_admin(request: Request) -> security.SessionClaims:
    claims = _require_user(request)
    if "auth.admin" not in claims.permissions:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin permission required")
    return claims


# --- cookie helpers ---------------------------------------------------------

def _set_session_cookie(response: Response, token: str, request: Request) -> None:
    domain = security.cookie_domain_for(request)
    response.set_cookie(
        key=settings().cookie_name,
        value=token,
        max_age=settings().cookie_ttl_seconds,
        path="/",
        domain=domain,         # None ⇒ host-only cookie (safer fallback)
        secure=True,
        httponly=True,
        samesite="lax",
    )


def _clear_session_cookie(response: Response, request: Request) -> None:
    domain = security.cookie_domain_for(request)
    response.delete_cookie(
        key=settings().cookie_name,
        path="/",
        domain=domain,
    )


# Wire the password / invite / reset router and the JSON CRUD router. Both
# need access to the same Templates instance and cookie helpers, so we hand
# them in here rather than letting them re-derive the logic.
routes_password.init(templates)
routes_password.configure_cookies(set_cookie=_set_session_cookie, clear_cookie=_clear_session_cookie)
routes_telegram.init(templates)
app.include_router(routes_password.router)
app.include_router(routes_api.router)
app.include_router(routes_telegram.router)


# --- public routes ----------------------------------------------------------

@app.get("/healthz")
def healthz() -> dict:
    return {"ok": True}


FALLBACK_TARGET_COOKIE = "rndexp_target"


@app.get("/", response_class=HTMLResponse)
def login_page(request: Request, target: str = ""):
    # If a `?target=` query param wasn't provided, fall back to the
    # `rndexp_target` cookie set by the Caddy `rndexp_auth_forward` snippet
    # on the upstream 401. Either source is validated through is_safe_target.
    if not target:
        target = request.cookies.get(FALLBACK_TARGET_COOKIE, "")
    safe_target = target if security.is_safe_target(target, request) else ""

    # If they're already signed in and we have a safe target, bounce immediately.
    claims = _current_claims(request)
    if claims and safe_target:
        resp = RedirectResponse(url=safe_target, status_code=302)
        _clear_target_cookie(resp, request)
        return resp

    start_url = "/auth/google/start"
    if safe_target:
        from urllib.parse import urlencode
        start_url = f"/auth/google/start?{urlencode({'target': safe_target})}"
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "target": safe_target,
            "start_url": start_url,
            "google_configured": settings().google_configured(),
            "error": None,
            "email": "",
        },
    )


def _clear_target_cookie(response: Response, request: Request) -> None:
    domain = security.cookie_domain_for(request)
    response.delete_cookie(FALLBACK_TARGET_COOKIE, path="/", domain=domain)


@app.get("/auth/google/start")
def google_start(request: Request, target: str = ""):
    if not settings().google_configured():
        raise HTTPException(500, "Google OAuth is not configured (set AUTH_GOOGLE_CLIENT_ID/SECRET)")
    safe_target = target if security.is_safe_target(target, request) else ""
    nonce = google.new_nonce()
    state = security.encode_state(safe_target or None, nonce)
    redirect_uri = f"{security.base_url_for(request)}/auth/google/callback"
    url = google.authorize_url(redirect_uri=redirect_uri, state=state)
    return RedirectResponse(url=url, status_code=302)


@app.get("/auth/google/callback")
def google_callback(
    request: Request,
    code: str = "",
    state: str = "",
    error: str = "",
    s: Session = Depends(_db_session),
):
    if error:
        raise HTTPException(400, f"Google returned error: {error}")
    if not code or not state:
        raise HTTPException(400, "Missing code or state")
    state_data = security.decode_state(state)
    if state_data is None:
        raise HTTPException(400, "Invalid or expired state")
    redirect_uri = f"{security.base_url_for(request)}/auth/google/callback"
    try:
        token_resp = google.exchange_code(code=code, redirect_uri=redirect_uri)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"Google token exchange failed: {e}")
    id_token = token_resp.get("id_token")
    if not id_token:
        raise HTTPException(502, "Google response missing id_token")
    try:
        claims = google.verify_id_token(id_token)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, f"id_token verification failed: {e}")
    if not claims.get("email_verified"):
        raise HTTPException(403, "Google account email is not verified")

    user = db.upsert_google_user(
        s,
        google_sub=str(claims["sub"]),
        email=str(claims["email"]).lower(),
        name=str(claims.get("name") or ""),
        picture_url=str(claims.get("picture") or ""),
        bootstrap_admin_email=settings().initial_admin_email or None,
    )

    session_token = security.encode_session(
        sub=user.id,
        email=user.email,
        name=user.name,
        picture=user.picture_url,
        roles=user.role_slugs(),
        permissions=user.permission_slugs(),
    )

    target = (state_data.get("target") or "").strip()
    # Same fallback ladder as the login page: use the upstream-set cookie
    # if the OAuth `state` didn't carry a target (e.g. user opened /auth/
    # google/start manually).
    if not target:
        target = request.cookies.get(FALLBACK_TARGET_COOKIE, "")
    if target and security.is_safe_target(target, request):
        resp = RedirectResponse(url=target, status_code=302)
    else:
        resp = RedirectResponse(url="/me", status_code=302)
    _set_session_cookie(resp, session_token, request)
    _clear_target_cookie(resp, request)
    return resp


@app.get("/me")
def me(request: Request):
    claims = _current_claims(request)
    if claims is None:
        return JSONResponse({"authenticated": False}, status_code=401)
    return {
        "authenticated": True,
        "sub": claims.sub,
        "email": claims.email,
        "name": claims.name,
        "picture": claims.picture,
        "roles": claims.roles,
        "permissions": claims.permissions,
    }


@app.get("/verify")
def verify(request: Request):
    """For Caddy `forward_auth`: 200 + headers if signed in, 401 otherwise."""
    claims = _current_claims(request)
    if claims is None:
        return Response(status_code=401)
    return Response(
        status_code=200,
        headers={
            "X-Auth-Sub": claims.sub,
            "X-Auth-Email": claims.email,
            "X-Auth-Roles": ",".join(claims.roles),
            "X-Auth-Permissions": ",".join(claims.permissions),
        },
    )


@app.post("/logout")
def logout(request: Request, target: str = ""):
    if target and security.is_safe_target(target, request):
        resp = RedirectResponse(url=target, status_code=302)
    else:
        resp = RedirectResponse(url="/", status_code=302)
    _clear_session_cookie(resp, request)
    return resp


# --- admin routes -----------------------------------------------------------

@app.get("/admin", response_class=HTMLResponse)
def admin_page(
    request: Request,
    me: Annotated[security.SessionClaims, Depends(_require_admin)],
    s: Session = Depends(_db_session),
):
    users = list(s.scalars(select(db.User).order_by(db.User.email)).all())
    roles = list(s.scalars(select(db.Role).order_by(db.Role.slug)).all())
    perms = list(s.scalars(select(db.Permission).order_by(db.Permission.slug)).all())
    return templates.TemplateResponse(
        request,
        "admin.html",
        {"me": me, "users": users, "roles": roles, "permissions": perms},
    )


@app.post("/admin/roles")
def admin_create_role(
    _: Annotated[security.SessionClaims, Depends(_require_admin)],
    slug: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    s: Session = Depends(_db_session),
):
    slug = slug.strip().lower()
    if not slug:
        raise HTTPException(400, "slug required")
    if s.scalar(select(db.Role).where(db.Role.slug == slug)):
        raise HTTPException(409, "role already exists")
    s.add(db.Role(slug=slug, description=description))
    s.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/permissions")
def admin_create_permission(
    _: Annotated[security.SessionClaims, Depends(_require_admin)],
    slug: Annotated[str, Form()],
    description: Annotated[str, Form()] = "",
    s: Session = Depends(_db_session),
):
    slug = slug.strip().lower()
    if not slug:
        raise HTTPException(400, "slug required")
    if s.scalar(select(db.Permission).where(db.Permission.slug == slug)):
        raise HTTPException(409, "permission already exists")
    s.add(db.Permission(slug=slug, description=description))
    s.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/users/{user_id}/roles")
def admin_grant_role(
    user_id: int,
    _: Annotated[security.SessionClaims, Depends(_require_admin)],
    role_slug: Annotated[str, Form()],
    s: Session = Depends(_db_session),
):
    user = s.get(db.User, user_id)
    role = s.scalar(select(db.Role).where(db.Role.slug == role_slug.strip().lower()))
    if not user or not role:
        raise HTTPException(404, "user or role not found")
    if role not in user.roles:
        user.roles.append(role)
        s.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/users/{user_id}/roles/{role_slug}/revoke")
def admin_revoke_role(
    user_id: int,
    role_slug: str,
    _: Annotated[security.SessionClaims, Depends(_require_admin)],
    s: Session = Depends(_db_session),
):
    user = s.get(db.User, user_id)
    role = s.scalar(select(db.Role).where(db.Role.slug == role_slug.strip().lower()))
    if not user or not role:
        raise HTTPException(404, "user or role not found")
    if role in user.roles:
        user.roles.remove(role)
        s.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.post("/admin/roles/{role_slug}/permissions")
def admin_attach_permission(
    role_slug: str,
    _: Annotated[security.SessionClaims, Depends(_require_admin)],
    permission_slug: Annotated[str, Form()],
    s: Session = Depends(_db_session),
):
    role = s.scalar(select(db.Role).where(db.Role.slug == role_slug.strip().lower()))
    perm = s.scalar(select(db.Permission).where(db.Permission.slug == permission_slug.strip().lower()))
    if not role or not perm:
        raise HTTPException(404, "role or permission not found")
    if perm not in role.permissions:
        role.permissions.append(perm)
        s.commit()
    return RedirectResponse(url="/admin", status_code=303)
