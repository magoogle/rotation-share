"""
UniversalRotation profile-sharing server.

Public client contract (consumed by `cloud_share.lua` in UR):

  POST   /api/profiles
  PATCH  /api/profiles/{code}
  GET    /api/profiles?class=<class>
  GET    /api/profiles/{code}

Auth on those endpoints uses X-API-Key (shared client secret embedded in
the Lua plugin).  Per-profile edits additionally require a `creator_token`
returned at create time.

The /admin UI + /admin/api/* endpoints are operator-only and use per-user
accounts ONLY.  Login at /admin/api/auth/login takes {username, password}
and returns a signed bearer token that the UI attaches as X-Admin-Session
on every subsequent admin request.  Roles:
    superadmin  -- full access incl. user management
    editor      -- can manage profiles but not users

ROTATION_SHARE_ADMIN_KEY is still required at startup, but it is NO LONGER
a login credential -- it is purely the HMAC key used to sign session
tokens.  Rotating it invalidates every existing token (every admin must
re-login), which is the intended emergency-revocation path.

Bootstrap: a fresh deploy with an empty `users` table can be seeded by
setting ROTATION_SHARE_BOOTSTRAP_USER=username:password[:role] in the
environment.  The user is created on the first startup that finds zero
users; subsequent restarts no-op.

Profiles can be created / edited from the admin UI (any admin role) in
addition to the plugin's public CREATE/PATCH path -- admin edits bypass
the creator_token check.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse


# ── Config ──────────────────────────────────────────────────────────────────

ROOT       = Path(os.environ.get('ROTATION_SHARE_ROOT', '/data'))
DB_PATH    = ROOT / 'profiles.sqlite3'
API_KEY    = (os.environ.get('ROTATION_SHARE_API_KEY')   or '').strip()
ADMIN_KEY  = (os.environ.get('ROTATION_SHARE_ADMIN_KEY') or '').strip()
MAX_BYTES  = int(os.environ.get('ROTATION_SHARE_MAX_BYTES', str(256 * 1024)))

_CLASS_RE   = re.compile(r'^[A-Za-z0-9_\-]{1,32}$')

# Codes use an unambiguous alphabet (no 0/O, no 1/I/L).
_CODE_ALPHA = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
_CODE_LEN   = 6
_CODE_RE    = re.compile(rf'^[{re.escape(_CODE_ALPHA)}]{{4,12}}$')

_USERNAME_RE = re.compile(r'^[A-Za-z0-9_\-\.]{2,64}$')
_VALID_ROLES = ('superadmin', 'editor')

# Session token TTL.  7 days is comfortable for an admin panel that
# people leave open in a browser tab.  Rotating ADMIN_KEY is the
# emergency-revocation lever -- it changes _SESSION_SECRET so every
# outstanding token stops verifying immediately.
_SESSION_TTL_S = 7 * 24 * 3600

if not API_KEY:
    raise RuntimeError('ROTATION_SHARE_API_KEY is required')
if not ADMIN_KEY:
    raise RuntimeError('ROTATION_SHARE_ADMIN_KEY is required')

ROOT.mkdir(parents=True, exist_ok=True)


# ── Crypto helpers ──────────────────────────────────────────────────────────

# Session-signing secret derived deterministically from ADMIN_KEY so the
# operator doesn't have to manage another env var, and so secret
# rotations happen by changing ADMIN_KEY (which already invalidates
# every saved session token, since the HMAC stops verifying).
_SESSION_SECRET = hmac.new(
    ADMIN_KEY.encode('utf-8'), b'rotation-share-session-v1', hashlib.sha256
).digest()


def _b64u_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')


def _b64u_decode(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256, 240k iterations, 16-byte random salt.
    Format: 'pbkdf2_sha256$<iters>$<b64salt>$<b64hash>'.  Stdlib only."""
    iters = 240_000
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters)
    return f'pbkdf2_sha256${iters}${_b64u_encode(salt)}${_b64u_encode(digest)}'


def _verify_password(password: str, encoded: str) -> bool:
    try:
        algo, iters_s, salt_b64, hash_b64 = encoded.split('$', 3)
    except ValueError:
        return False
    if algo != 'pbkdf2_sha256':
        return False
    try:
        iters = int(iters_s)
    except ValueError:
        return False
    salt = _b64u_decode(salt_b64)
    expected = _b64u_decode(hash_b64)
    actual = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iters)
    return secrets.compare_digest(actual, expected)


def _make_session(claims: dict) -> str:
    """Sign a JSON claims dict with HMAC-SHA256 derived from ADMIN_KEY.
    Output: '<b64-claims>.<b64-sig>'.  Plain enough to validate without
    pulling in PyJWT or similar."""
    body = json.dumps(claims, separators=(',', ':'), sort_keys=True).encode('utf-8')
    sig  = hmac.new(_SESSION_SECRET, body, hashlib.sha256).digest()
    return f'{_b64u_encode(body)}.{_b64u_encode(sig)}'


def _read_session(token: str) -> Optional[dict]:
    if not token or '.' not in token:
        return None
    try:
        body_b64, sig_b64 = token.split('.', 1)
        body = _b64u_decode(body_b64)
        sig  = _b64u_decode(sig_b64)
    except Exception:
        return None
    expected = hmac.new(_SESSION_SECRET, body, hashlib.sha256).digest()
    if not hmac.compare_digest(sig, expected):
        return None
    try:
        claims = json.loads(body)
    except Exception:
        return None
    if not isinstance(claims, dict):
        return None
    exp = claims.get('exp')
    if not isinstance(exp, (int, float)) or exp < time.time():
        return None
    return claims


# ── DB ──────────────────────────────────────────────────────────────────────

_LOCK = threading.RLock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS profiles (
    code           TEXT PRIMARY KEY,
    class          TEXT NOT NULL,
    name           TEXT NOT NULL,
    data           TEXT NOT NULL,
    creator_token  TEXT NOT NULL,
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS profiles_class      ON profiles(class);
CREATE INDEX IF NOT EXISTS profiles_updated_at ON profiles(updated_at);

CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    username       TEXT UNIQUE NOT NULL COLLATE NOCASE,
    password_hash  TEXT NOT NULL,
    role           TEXT NOT NULL,
    created_at     REAL NOT NULL,
    updated_at     REAL NOT NULL
);
"""

_conn = sqlite3.connect(
    str(DB_PATH),
    check_same_thread=False,
    timeout=10.0,
    isolation_level=None,
)
_conn.row_factory = sqlite3.Row
_conn.execute('PRAGMA journal_mode=WAL')
_conn.execute('PRAGMA synchronous=NORMAL')
_conn.executescript(_SCHEMA)
# (Bootstrap-first-user check is at the bottom of this module; it
#  needs _query_one + _write + _hash_password defined first.)


@contextmanager
def _write():
    with _LOCK:
        cur = _conn.cursor()
        try:
            cur.execute('BEGIN IMMEDIATE')
            yield cur
            cur.execute('COMMIT')
        except Exception:
            cur.execute('ROLLBACK')
            raise
        finally:
            cur.close()


def _query_one(sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
    with _LOCK:
        cur = _conn.execute(sql, params)
        try:
            return cur.fetchone()
        finally:
            cur.close()


def _query(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    with _LOCK:
        cur = _conn.execute(sql, params)
        try:
            return cur.fetchall()
        finally:
            cur.close()


# ── Helpers ─────────────────────────────────────────────────────────────────

def _gen_code() -> str:
    for _ in range(8):
        code = ''.join(secrets.choice(_CODE_ALPHA) for _ in range(_CODE_LEN))
        if _query_one('SELECT 1 FROM profiles WHERE code = ?', (code,)) is None:
            return code
    return ''.join(secrets.choice(_CODE_ALPHA) for _ in range(_CODE_LEN + 4))


def _err(msg: str, status: int = 400) -> JSONResponse:
    return JSONResponse({'ok': False, 'error': msg}, status_code=status)


def _check_key(presented: Optional[str]) -> None:
    if not presented or not secrets.compare_digest(presented.strip(), API_KEY):
        raise HTTPException(status_code=401, detail='bad api key')


def _check_class(class_key: str) -> None:
    if not class_key or not _CLASS_RE.match(class_key):
        raise HTTPException(status_code=400, detail='bad class key')


def _check_code(code: str) -> None:
    if not code or not _CODE_RE.match(code):
        raise HTTPException(status_code=400, detail='bad code')


def _admin_principal(session_token: Optional[str]) -> dict:
    """Resolve the admin caller from a signed session token.  Returns:
        {'role': 'superadmin'|'editor', 'user_id': int, 'username': str}
    Raises 401 when the token is missing/expired/forged or the user has
    been deleted.
    """
    if session_token:
        claims = _read_session(session_token.strip())
        if claims:
            role = claims.get('role')
            uid  = claims.get('user_id')
            if role in _VALID_ROLES and isinstance(uid, int):
                # Re-verify the user row still exists (deleted accounts
                # whose tokens haven't expired yet) and pull the LIVE
                # role -- a demotion takes effect on the next request,
                # not when the token expires.
                row = _query_one(
                    'SELECT username, role FROM users WHERE id = ?', (uid,))
                if row is not None:
                    return {
                        'role':     str(row['role']),
                        'user_id':  uid,
                        'username': str(row['username']),
                    }
    raise HTTPException(status_code=401, detail='unauthorized')


def _require_role(principal: dict, *roles: str) -> None:
    if principal.get('role') not in roles:
        raise HTTPException(status_code=403, detail='forbidden')


# ── App ─────────────────────────────────────────────────────────────────────

app = FastAPI(title='rotation-share', version='2.0')

_ADMIN_HTML_PATH = Path(__file__).parent / 'admin.html'


@app.get('/health')
def health():
    n = _query_one('SELECT COUNT(*) AS n FROM profiles')
    u = _query_one('SELECT COUNT(*) AS n FROM users')
    return {
        'ok':       True,
        'profiles': int(n['n']) if n else 0,
        'users':    int(u['n']) if u else 0,
    }


# ── Public client API ───────────────────────────────────────────────────────

@app.post('/api/profiles')
async def create_profile(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias='X-API-Key'),
):
    _check_key(x_api_key)

    raw = await request.body()
    if len(raw) > MAX_BYTES:
        return _err(f'profile too large ({len(raw)} > {MAX_BYTES})', 413)

    try:
        body = await request.json()
    except Exception:
        return _err('invalid json body')
    if not isinstance(body, dict):
        return _err('body must be a json object')

    class_key = (body.get('class') or '').strip()
    name      = (body.get('name')  or '').strip()
    data      = body.get('data')

    if not class_key or not _CLASS_RE.match(class_key):
        return _err('bad or missing class')
    if not name:
        return _err('missing name')
    if not isinstance(data, str) or not data:
        return _err('data must be a non-empty string')
    if len(name) > 200:
        name = name[:200]

    code  = _gen_code()
    token = secrets.token_hex(16)
    now   = time.time()

    with _write() as c:
        c.execute("""
            INSERT INTO profiles(code, class, name, data, creator_token,
                                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (code, class_key, name, data, token, now, now))

    return {'ok': True, 'code': code, 'creator_token': token}


@app.patch('/api/profiles/{code}')
async def update_profile(
    code: str,
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias='X-API-Key'),
):
    _check_key(x_api_key)
    _check_code(code)

    raw = await request.body()
    if len(raw) > MAX_BYTES:
        return _err(f'profile too large ({len(raw)} > {MAX_BYTES})', 413)

    try:
        body = await request.json()
    except Exception:
        return _err('invalid json body')
    if not isinstance(body, dict):
        return _err('body must be a json object')

    data  = body.get('data')
    token = (body.get('creator_token') or '').strip()
    if not isinstance(data, str) or not data:
        return _err('data must be a non-empty string')
    if not token:
        return _err('missing creator_token')

    row = _query_one(
        'SELECT creator_token FROM profiles WHERE code = ?', (code,))
    if row is None:
        return _err('profile not found', 404)
    if not secrets.compare_digest(str(row['creator_token']), token):
        return _err('bad creator_token', 403)

    with _write() as c:
        c.execute("""
            UPDATE profiles
               SET data = ?, updated_at = ?
             WHERE code = ?
        """, (data, time.time(), code))

    return {'ok': True}


@app.get('/api/profiles')
def list_profiles(
    class_: str = Query(..., alias='class'),
    x_api_key: Optional[str] = Header(default=None, alias='X-API-Key'),
):
    _check_key(x_api_key)
    _check_class(class_)

    rows = _query("""
        SELECT code, name, updated_at
          FROM profiles
         WHERE class = ?
         ORDER BY updated_at DESC
         LIMIT 500
    """, (class_,))
    return [
        {'code': r['code'], 'name': r['name'], 'updated_at': float(r['updated_at'])}
        for r in rows
    ]


@app.get('/api/profiles/{code}')
def get_profile(
    code: str,
    x_api_key: Optional[str] = Header(default=None, alias='X-API-Key'),
):
    _check_key(x_api_key)
    _check_code(code)

    row = _query_one("""
        SELECT code, class, name, data, updated_at
          FROM profiles
         WHERE code = ?
    """, (code,))
    if row is None:
        return _err('profile not found', 404)
    return {
        'code':       row['code'],
        'class':      row['class'],
        'name':       row['name'],
        'data':       row['data'],
        'updated_at': float(row['updated_at']),
    }


# ── Admin UI ────────────────────────────────────────────────────────────────

@app.get('/admin', response_class=HTMLResponse)
@app.get('/admin/', response_class=HTMLResponse)
def admin_ui():
    try:
        return HTMLResponse(_ADMIN_HTML_PATH.read_text(encoding='utf-8'))
    except OSError:
        return HTMLResponse('<h1>admin.html missing</h1>', status_code=500)


# ── Admin auth ──────────────────────────────────────────────────────────────

@app.post('/admin/api/auth/login')
async def admin_auth_login(request: Request):
    """Per-user login.  Accepts {username, password} and returns a
    signed bearer token in {ok, token, role, username, user_id}.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    if not username or not password:
        return _err('missing credentials', 401)

    row = _query_one(
        'SELECT id, username, password_hash, role FROM users WHERE username = ?',
        (username,),
    )
    if row is None or not _verify_password(password, str(row['password_hash'])):
        return _err('invalid username or password', 401)

    token = _make_session({
        'role':     str(row['role']),
        'user_id':  int(row['id']),
        'username': str(row['username']),
        'iat':      int(time.time()),
        'exp':      int(time.time() + _SESSION_TTL_S),
    })
    return {'ok': True, 'token': token, 'role': str(row['role']),
            'username': str(row['username']), 'user_id': int(row['id'])}


@app.get('/admin/api/me')
def admin_me(
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    p = _admin_principal(x_admin_session)
    return {'ok': True, 'role': p['role'], 'username': p['username'],
            'user_id': p['user_id']}


# ── Spell-name reference data ──────────────────────────────────────────────
# Static id→name map shipped alongside the app.  Built once via
# scripts/build_spell_names.py from the user's curated list + the
# d4data-master Power dump.  Served as plain JSON; no auth required --
# it's reference data the admin UI overlays on profile editing.

_SPELL_NAMES_PATH = Path(__file__).parent / 'static' / 'spell_names.json'


@app.get('/admin/api/spell_names')
def admin_spell_names():
    try:
        return JSONResponse(content=json.loads(
            _SPELL_NAMES_PATH.read_text(encoding='utf-8')
        ))
    except OSError:
        return _err('spell_names.json missing on the server', 500)
    except Exception as e:
        return _err(f'spell_names.json: {e}', 500)


# ── Admin: profiles ────────────────────────────────────────────────────────

@app.get('/admin/api/profiles')
def admin_list_profiles(
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    _admin_principal(x_admin_session)
    rows = _query("""
        SELECT code, class, name, LENGTH(data) AS bytes,
               created_at, updated_at
          FROM profiles
         ORDER BY updated_at DESC
    """)
    return [
        {
            'code':       r['code'],
            'class':      r['class'],
            'name':       r['name'],
            'bytes':      int(r['bytes']),
            'created_at': float(r['created_at']),
            'updated_at': float(r['updated_at']),
        }
        for r in rows
    ]


@app.get('/admin/api/profiles/{code}')
def admin_get_profile(
    code: str,
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    _admin_principal(x_admin_session)
    _check_code(code)
    row = _query_one("""
        SELECT code, class, name, data, creator_token,
               created_at, updated_at, LENGTH(data) AS bytes
          FROM profiles WHERE code = ?
    """, (code,))
    if row is None:
        return _err('profile not found', 404)
    return {
        'code':          row['code'],
        'class':         row['class'],
        'name':          row['name'],
        'data':          row['data'],
        'bytes':         int(row['bytes']),
        'creator_token': row['creator_token'],
        'created_at':    float(row['created_at']),
        'updated_at':    float(row['updated_at']),
    }


@app.post('/admin/api/profiles')
async def admin_create_profile(
    request: Request,
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    """Admin-authored profile create.  Bypasses the public client's
    X-API-Key check (admin auth implies ability) but otherwise produces
    the same row shape, so the plugin can fetch it via the normal
    public GET path with just the share code."""
    _admin_principal(x_admin_session)

    raw = await request.body()
    if len(raw) > MAX_BYTES:
        return _err(f'profile too large ({len(raw)} > {MAX_BYTES})', 413)

    try:
        body = await request.json()
    except Exception:
        return _err('invalid json body')
    if not isinstance(body, dict):
        return _err('body must be a json object')

    class_key = (body.get('class') or '').strip()
    name      = (body.get('name')  or '').strip()
    data      = body.get('data')

    if not class_key or not _CLASS_RE.match(class_key):
        return _err('bad or missing class')
    if not name:
        return _err('missing name')
    if not isinstance(data, str) or not data:
        return _err('data must be a non-empty string')
    if len(name) > 200:
        name = name[:200]

    # JSON validation: profile data must parse as JSON.  The plugin
    # consumes it as a JSON string; rejecting malformed input here saves
    # the user the round trip of pushing a profile that won't load.
    try:
        json.loads(data)
    except Exception as e:
        return _err(f'data is not valid JSON: {e}')

    code  = _gen_code()
    token = secrets.token_hex(16)
    now   = time.time()

    with _write() as c:
        c.execute("""
            INSERT INTO profiles(code, class, name, data, creator_token,
                                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (code, class_key, name, data, token, now, now))

    return {'ok': True, 'code': code, 'creator_token': token}


@app.patch('/admin/api/profiles/{code}')
async def admin_update_profile(
    code: str,
    request: Request,
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    """Admin-side edit.  Updates any combination of class/name/data
    without requiring the creator_token (admin auth implies ability)."""
    _admin_principal(x_admin_session)
    _check_code(code)

    raw = await request.body()
    if len(raw) > MAX_BYTES:
        return _err(f'profile too large ({len(raw)} > {MAX_BYTES})', 413)

    try:
        body = await request.json()
    except Exception:
        return _err('invalid json body')
    if not isinstance(body, dict):
        return _err('body must be a json object')

    fields, params = [], []
    if 'class' in body:
        cls = (body.get('class') or '').strip()
        if not cls or not _CLASS_RE.match(cls):
            return _err('bad class')
        fields.append('class = ?'); params.append(cls)
    if 'name' in body:
        name = (body.get('name') or '').strip()
        if not name:
            return _err('missing name')
        if len(name) > 200:
            name = name[:200]
        fields.append('name = ?'); params.append(name)
    if 'data' in body:
        data = body.get('data')
        if not isinstance(data, str) or not data:
            return _err('data must be a non-empty string')
        try:
            json.loads(data)
        except Exception as e:
            return _err(f'data is not valid JSON: {e}')
        fields.append('data = ?'); params.append(data)

    if not fields:
        return _err('nothing to update (supply at least one of class/name/data)')

    row = _query_one('SELECT 1 FROM profiles WHERE code = ?', (code,))
    if row is None:
        return _err('profile not found', 404)

    fields.append('updated_at = ?'); params.append(time.time())
    params.append(code)
    sql = f"UPDATE profiles SET {', '.join(fields)} WHERE code = ?"

    with _write() as c:
        c.execute(sql, params)

    return {'ok': True}


@app.delete('/admin/api/profiles/{code}')
def admin_delete_profile(
    code: str,
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    _admin_principal(x_admin_session)
    _check_code(code)
    with _write() as c:
        c.execute('DELETE FROM profiles WHERE code = ?', (code,))
        deleted = c.rowcount
    if deleted == 0:
        return _err('profile not found', 404)
    return {'ok': True, 'deleted': deleted}


@app.post('/admin/api/bulk-delete')
async def admin_bulk_delete(
    request: Request,
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    """Delete by explicit code list, by class, or by 'older than N days'.
    All three filters can be combined; at least one must be supplied to
    avoid a stray click wiping the table."""
    _admin_principal(x_admin_session)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}

    codes        = body.get('codes')
    class_filter = (body.get('class') or '').strip() or None
    older_days   = body.get('older_than_days')

    where: list[str] = []
    params: list = []

    if isinstance(codes, list) and codes:
        clean = [c for c in codes if isinstance(c, str) and _CODE_RE.match(c)]
        if not clean:
            return _err('codes list contained no valid codes')
        where.append(f"code IN ({','.join('?' for _ in clean)})")
        params.extend(clean)

    if class_filter:
        if not _CLASS_RE.match(class_filter):
            return _err('bad class filter')
        where.append('class = ?')
        params.append(class_filter)

    if older_days is not None:
        try:
            days = float(older_days)
        except (TypeError, ValueError):
            return _err('older_than_days must be a number')
        if days < 0:
            return _err('older_than_days must be >= 0')
        cutoff = time.time() - days * 86400.0
        where.append('updated_at < ?')
        params.append(cutoff)

    if not where:
        return _err('refuse to bulk-delete with no filter; supply codes, class, or older_than_days')

    sql = f"DELETE FROM profiles WHERE {' AND '.join(where)}"
    with _write() as c:
        c.execute(sql, params)
        deleted = c.rowcount
    return {'ok': True, 'deleted': int(deleted)}


# ── Admin: users ───────────────────────────────────────────────────────────

@app.get('/admin/api/users')
def admin_list_users(
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    p = _admin_principal(x_admin_session)
    _require_role(p, 'superadmin')
    rows = _query("""
        SELECT id, username, role, created_at, updated_at
          FROM users
         ORDER BY username COLLATE NOCASE
    """)
    return [
        {
            'id':         int(r['id']),
            'username':   str(r['username']),
            'role':       str(r['role']),
            'created_at': float(r['created_at']),
            'updated_at': float(r['updated_at']),
        }
        for r in rows
    ]


@app.post('/admin/api/users')
async def admin_create_user(
    request: Request,
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    p = _admin_principal(x_admin_session)
    _require_role(p, 'superadmin')

    try:
        body = await request.json()
    except Exception:
        return _err('invalid json body')
    if not isinstance(body, dict):
        return _err('body must be a json object')

    username = (body.get('username') or '').strip()
    password = body.get('password') or ''
    role     = (body.get('role') or '').strip()

    if not _USERNAME_RE.match(username):
        return _err('bad username (2-64 chars, letters/digits/_-./)')
    if not isinstance(password, str) or len(password) < 8:
        return _err('password must be at least 8 characters')
    if role not in _VALID_ROLES:
        return _err(f'role must be one of {list(_VALID_ROLES)}')

    if _query_one('SELECT 1 FROM users WHERE username = ?', (username,)) is not None:
        return _err('username already taken', 409)

    now = time.time()
    with _write() as c:
        c.execute("""
            INSERT INTO users(username, password_hash, role,
                              created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """, (username, _hash_password(password), role, now, now))
        user_id = c.lastrowid

    return {'ok': True, 'id': user_id, 'username': username, 'role': role}


@app.patch('/admin/api/users/{user_id}')
async def admin_update_user(
    user_id: int,
    request: Request,
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    p = _admin_principal(x_admin_session)
    _require_role(p, 'superadmin')

    try:
        body = await request.json()
    except Exception:
        return _err('invalid json body')
    if not isinstance(body, dict):
        return _err('body must be a json object')

    row = _query_one('SELECT id, role FROM users WHERE id = ?', (user_id,))
    if row is None:
        return _err('user not found', 404)

    fields, params = [], []
    if 'password' in body:
        password = body.get('password') or ''
        if not isinstance(password, str) or len(password) < 8:
            return _err('password must be at least 8 characters')
        fields.append('password_hash = ?')
        params.append(_hash_password(password))
    if 'role' in body:
        role = (body.get('role') or '').strip()
        if role not in _VALID_ROLES:
            return _err(f'role must be one of {list(_VALID_ROLES)}')
        # Refuse to leave the system with zero superadmins.  We allow
        # demoting a superadmin to editor only if at least one other
        # superadmin exists in the users table -- with the master-key
        # login removed there is no other escape hatch from a
        # zero-superadmin state short of editing the DB by hand.
        if str(row['role']) == 'superadmin' and role != 'superadmin':
            cnt = _query_one(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'superadmin' AND id != ?",
                (user_id,),
            )
            if cnt and int(cnt['n']) == 0:
                return _err('cannot demote the only remaining superadmin user', 400)
        fields.append('role = ?')
        params.append(role)

    if not fields:
        return _err('nothing to update (supply password or role)')

    fields.append('updated_at = ?'); params.append(time.time())
    params.append(user_id)
    sql = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"

    with _write() as c:
        c.execute(sql, params)

    return {'ok': True}


@app.delete('/admin/api/users/{user_id}')
def admin_delete_user(
    user_id: int,
    x_admin_session: Optional[str] = Header(default=None, alias='X-Admin-Session'),
):
    p = _admin_principal(x_admin_session)
    _require_role(p, 'superadmin')

    # Prevent the operator from deleting the user they're logged in as
    # -- the post-delete next request would 401 with no session left.
    if p['user_id'] == user_id:
        return _err('cannot delete the user you are logged in as', 400)

    row = _query_one('SELECT role FROM users WHERE id = ?', (user_id,))
    if row is None:
        return _err('user not found', 404)
    if str(row['role']) == 'superadmin':
        cnt = _query_one(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'superadmin' AND id != ?",
            (user_id,),
        )
        if cnt and int(cnt['n']) == 0:
            return _err('cannot delete the only remaining superadmin user', 400)

    with _write() as c:
        c.execute('DELETE FROM users WHERE id = ?', (user_id,))
        deleted = c.rowcount
    if deleted == 0:
        return _err('user not found', 404)
    return {'ok': True, 'deleted': deleted}


# ── Bootstrap the first admin ───────────────────────────────────────────────
# Runs at module load (after every helper above is defined).  If the
# `users` table is empty AND ROTATION_SHARE_BOOTSTRAP_USER is set as
# "username:password[:role]", create that row once.  Subsequent restarts
# are no-ops because the table is no longer empty.  This is the recovery
# path for fresh deploys + lockouts now that the master-key login is gone.
def _bootstrap_first_user() -> None:
    row = _query_one('SELECT COUNT(*) AS n FROM users')
    n_users = int(row['n']) if row else 0
    if n_users > 0:
        return
    spec = (os.environ.get('ROTATION_SHARE_BOOTSTRAP_USER') or '').strip()
    if not spec:
        print(
            '[rotation-share] WARNING: users table is empty and no '
            'ROTATION_SHARE_BOOTSTRAP_USER is set -- nobody can log in. '
            'Set ROTATION_SHARE_BOOTSTRAP_USER=user:pass[:role] in .env '
            'and restart, or insert a row directly into the users table.',
            flush=True,
        )
        return
    try:
        parts = spec.split(':')
        if len(parts) < 2:
            raise ValueError('expected "username:password[:role]"')
        u = parts[0].strip()
        p = parts[1]
        r = parts[2].strip() if len(parts) > 2 else 'superadmin'
        if not _USERNAME_RE.match(u):
            raise ValueError(f'bad username "{u}"')
        if r not in _VALID_ROLES:
            raise ValueError(f'bad role "{r}" (must be one of {list(_VALID_ROLES)})')
        if len(p) < 8:
            raise ValueError('password must be at least 8 characters')
        now = time.time()
        with _write() as c:
            c.execute(
                'INSERT INTO users(username, password_hash, role, '
                '                  created_at, updated_at) '
                'VALUES (?, ?, ?, ?, ?)',
                (u, _hash_password(p), r, now, now),
            )
        print(
            f'[rotation-share] bootstrap: created user "{u}" with role "{r}"',
            flush=True,
        )
    except Exception as e:
        print(f'[rotation-share] bootstrap FAILED: {e}', flush=True)


_bootstrap_first_user()
