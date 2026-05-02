# AGENTS.md — auth service

This is a service of the [rndexpart gateway](../../AGENTS.md). Read the gateway's AGENTS.md first.

## What this service is

A small FastAPI app that owns identity for the whole `rndexp.art` ecosystem.

- Public hostname: `auth.rndexp.art` (production), `auth.rndexp.localhost` (dev).
- Internal port: **8001**.
- Renders a login page with a "Sign in with Google" button.
- After successful Google OAuth, sets a cookie scoped to **`.rndexp.art`** (or `.rndexp.localhost` for dev) so every subdomain can read it, then redirects to the `target=` URL passed when the login page was opened.
- Owns a small SQLite database of users / roles / permissions.

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
