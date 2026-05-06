# rotation-share

Tiny FastAPI + SQLite server backing the **UniversalRotation** Lua plugin's
"share rotation profiles to the cloud" feature.  Source for the deployed
container at `https://share.d4data.live`.

## What's here

```
.
├── Dockerfile             # python:3.12-slim + uvicorn
├── docker-compose.yml     # binds 8001:8000, named volume for /data
├── requirements.txt       # fastapi + uvicorn
└── app/
    ├── main.py            # all endpoints (public + /admin)
    └── admin.html         # operator UI (login, profiles, users)
```

## Endpoints

### Public client API (used by `cloud_share.lua` in UR)

`X-API-Key` required (matches `ROTATION_SHARE_API_KEY`).

| Method  | Path                          | Notes                                   |
| ------- | ----------------------------- | --------------------------------------- |
| `POST`  | `/api/profiles`               | Create.  Returns `{code, creator_token}`. |
| `PATCH` | `/api/profiles/{code}`        | Update; requires the original `creator_token`. |
| `GET`   | `/api/profiles?class={class}` | List for a class; sorted by `updated_at` desc. |
| `GET`   | `/api/profiles/{code}`        | Fetch one.                              |

### Admin UI / API

UI at **`/admin`**.  Username + password only.  Login at
`/admin/api/auth/login` with `{username, password}` returns a signed bearer
token; the UI attaches it as `X-Admin-Session` on every request.  Roles:

- `superadmin` — full access including user management
- `editor`     — manage profiles only

`ROTATION_SHARE_ADMIN_KEY` is still required at startup but is **no longer a
login credential** — it derives the HMAC key that signs session tokens.
Rotating it instantly invalidates every outstanding token (every admin must
re-login).  That's the emergency-revocation lever.

Profiles can be **created** and **edited** in-browser (any admin role).
JSON validation runs server-side before save.

#### Bootstrapping the first user

A fresh deploy with an empty `users` table is a locked-out state.  Set:

```
ROTATION_SHARE_BOOTSTRAP_USER=username:password[:role]
```

in `.env` and start the container.  If `users` is empty, the row is created
once.  Subsequent restarts are no-ops.  Defaults to `role=superadmin`.

If you ever lose access without a working account, SSH to the host, edit
`/opt/rotation-share/.env`, add the env var, and `docker compose up -d`.

## Local quickstart

```bash
cp .env.example .env   # fill in keys
docker compose up --build -d
curl -fsS http://localhost:8001/health
```

## Deployment

The host runs `git pull` from this repo's `main` branch and rebuilds:

```bash
cd /opt/rotation-share
git pull --ff-only
docker compose up --build -d
```

The named `rotation-share-data` volume preserves `profiles.sqlite3` (and the
new `users` table) across container rebuilds.  The schema migrations are
inline in `_SCHEMA` and use `CREATE TABLE IF NOT EXISTS` so existing data
survives upgrades.
