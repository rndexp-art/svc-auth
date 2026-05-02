# auth service

Identity for the `rndexp.art` ecosystem. Google OAuth → signed cookie scoped to `.rndexp.art`, plus a small users/roles/permissions store.

See [AGENTS.md](AGENTS.md) for the full picture (env vars, Google setup, integration patterns).

## Local dev

From the gateway repo root:

```sh
tools/rndexp service enable auth --env local   # already enabled by default
tools/rndexp up
open https://auth.rndexp.localhost
```

## Public surface

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/` | Login page (`?target=` to bounce back after login) |
| `GET` | `/auth/google/start` | Begin Google OAuth flow |
| `GET` | `/auth/google/callback` | OAuth callback — sets cookie + redirects |
| `GET` | `/me` | Current user JSON (401 if not signed in) |
| `GET` | `/verify` | For Caddy `forward_auth` — 200 + headers, or 401 |
| `POST` | `/logout` | Clears cookie |
| `GET` | `/admin` | Admin UI (gated by `auth.admin` permission) |
| `GET` | `/healthz` | Liveness probe |

## Internal port

Listens on **8001**. Caddy reverse-proxies `auth:8001` over the project's docker network.
