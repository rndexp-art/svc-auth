# AGENTS.md — auth service

This is a service of the [rndexpart gateway](../../AGENTS.md). Read the gateway's AGENTS.md first.

## What this service is

A small FastAPI app that owns identity for the whole `rndexp.art` ecosystem.

- Public hostname: `auth.rndexp.art` (production), `auth.rndexp.localhost` (dev).
- Internal port: **8001**.
- Login page offers two paths: **Sign in with Google** and **email + password**. The same account can use either or both — Google sub and password hash live on the same row in `users`.
- After successful login, sets a cookie scoped to **`.rndexp.art`** (or `.rndexp.localhost` for dev) so every subdomain can read it, then redirects to the `target=` URL passed when the login page was opened.
- Owns a small SQLite database of users / roles / permissions, plus one-time `invite_tokens` and `password_reset_tokens` (sha256-hashed before storage; plaintext only ever exists in the URL emailed to the user).
- Exposes a JSON CRUD API under `/api/users` that the dashboard calls (cookie-forwarded admin session). The HTML `/admin` page is the legacy interface — both work and share the same DB.

## How other services use it

Two integration patterns:

1. **Forward-auth in Caddy** — point a site's matcher at `https://auth.rndexp.art/verify`; the auth service returns 200 with `X-Auth-Email` / `X-Auth-Roles` headers if the cookie is valid, 401 otherwise. See `caddy.fragment` for the snippet exposed.
2. **In-process JWT verify** — read the cookie `rndexp_auth`, decode HS256 with shared `AUTH_JWT_SECRET`. Claims include `sub`, `email`, `name`, `roles`, `permissions`, `exp`.

## What lives here

- `compose.fragment.yml` — service definition, included by the gateway compose.
- `caddy.fragment` — Caddy site block, concatenated into the gateway Caddyfile.
- `Dockerfile` — builds the FastAPI image (uv, Python 3.12 slim).
- `app/` — FastAPI source.
- `.env.example` — required env vars (set the real values in the gateway's `.env` / GH Secrets).

## Required env vars

| Var | Purpose |
|---|---|
| `AUTH_GOOGLE_CLIENT_ID` | Google OAuth 2.0 client id |
| `AUTH_GOOGLE_CLIENT_SECRET` | Google OAuth 2.0 client secret |
| `AUTH_JWT_SECRET` | 32+ byte random string used to sign session cookies |
| `AUTH_INITIAL_ADMIN_EMAIL` | This email gets the `admin` role on first login (bootstraps the system) |
| `AUTH_SMTP_*` (optional) | SMTP host/port/user/password/from for invite + reset emails. **If unset**, those flows still issue tokens but log the URL to stderr; the dashboard's admin UI surfaces the link so an operator can copy it manually. See `.env.example`. |

## Routes

| Path | Method | Purpose |
|---|---|---|
| `/` | GET | Login page (Google button + password form). |
| `/login` | POST | Password sign-in. |
| `/auth/google/start` / `/auth/google/callback` | GET | Google OAuth round trip. |
| `/forgot-password` | GET, POST | Request a reset email; always 200 to avoid account-existence enumeration. |
| `/reset-password/{token}` | GET, POST | Consume a one-time reset token, set a new password, sign in. |
| `/invite/{token}` | GET, POST | Consume a one-time invite token, set a password, sign in. |
| `/me` | GET | Current user JSON. |
| `/verify` | GET | Caddy `forward_auth` probe — 200 with X-Auth-* on valid cookie, 401 otherwise. |
| `/logout` | POST | Clear the cookie. |
| `/admin` | GET | Legacy HTML admin UI. |
| `/api/users` | GET, POST `/invite` | List users; create an invite. |
| `/api/users/{id}` | DELETE | Remove a user (rejects last-admin). |
| `/api/users/{id}/reset-password` | POST | Admin-triggered reset. |
| `/api/users/{id}/roles` | POST | Grant a role. |
| `/api/users/{id}/roles/{slug}` | DELETE | Revoke a role (rejects revoking the last admin's `admin`). |
| `/api/roles` | GET | Role slug list (used by the dashboard's role-picker). |

The service derives its own external URL and cookie domain from the inbound `Host` header at request time, so there is no `AUTH_BASE_URL` knob to keep in sync.

## Google OAuth setup (one-time)

1. Cloud Console → APIs & Services → Credentials → Create OAuth client ID (Web application).
2. Authorized redirect URIs:
   - `https://auth.rndexp.art/auth/google/callback`
   - `https://auth.rndexp.localhost/auth/google/callback` (for local dev)
3. Copy client id / secret into the gateway's `.env` and `.env.production`, then `tools/rndexp secrets push` from the gateway repo.

## Conventions

- Bind container ports inside the docker network only. Caddy is the public ingress.
- All hostnames in `caddy.fragment` use the production form (`*.rndexp.art`); the gateway's renderer rewrites them for local.
- This service is the only one that should write to the `auth_data` docker volume.

## Migration to a submodule

For now this lives in-tree under `services/auth/` rather than as a submodule like `services/neo4j`. To convert it once `rndexp-art/svc-auth` exists on GitHub:

```sh
# from the gateway repo root, having pushed services/auth/* to rndexp-art/svc-auth main + production:
git rm -r --cached services/auth
mv services/auth /tmp/auth-staging   # move out of the way
git submodule add https://github.com/rndexp-art/svc-auth.git services/auth
# then copy the staged files in and `git submodule update --remote`.
```
