#!/usr/bin/env python3
"""Production-oriented backend API + SQLite storage for SWOT Analyzer SaaS."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib.request import ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "swot.db"
MAX_BODY_BYTES = int(os.getenv("MAX_BODY_BYTES", "1000000"))
SESSION_COOKIE = "swot_session"
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "604800"))  # 7 days
APP_SECRET = os.getenv("APP_SECRET", "dev-only-change-me")
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "120"))

RATE_BUCKETS: dict[str, list[float]] = {}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_iso(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def normalize_target_url(raw: str) -> str:
    raw = (raw or "").strip()
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL must start with http:// or https://")
    if not parsed.netloc:
        raise ValueError("URL host is missing")
    return raw


def hash_password(password: str, salt_b64: str | None = None) -> tuple[str, str]:
    salt = base64.b64decode(salt_b64) if salt_b64 else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 120_000)
    return base64.b64encode(digest).decode("utf-8"), base64.b64encode(salt).decode("utf-8")


def hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def sign_session(payload: str) -> str:
    sig = hmac.new(APP_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_session(token: str) -> tuple[int, int] | None:
    try:
        payload, provided_sig = token.rsplit(".", 1)
        expected_sig = hmac.new(APP_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(provided_sig, expected_sig):
            return None
        user_id_s, exp_s = payload.split(":", 1)
        user_id, exp = int(user_id_s), int(exp_s)
        if exp < int(time.time()):
            return None
        return user_id, exp
    except Exception:
        return None


def build_session_cookie(user_id: int) -> str:
    exp = int(time.time()) + SESSION_TTL_SECONDS
    token = sign_session(f"{user_id}:{exp}")
    return f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL_SECONDS}"


def clear_session_cookie() -> str:
    return f"{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                plan TEXT NOT NULL DEFAULT 'free',
                created_at TEXT NOT NULL,
                last_login_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS api_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL UNIQUE,
                prefix TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )

        legacy_row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='analyses'"
        ).fetchone()
        if legacy_row:
            cols = [r[1] for r in conn.execute("PRAGMA table_info(analyses)").fetchall()]
            if "user_id" not in cols:
                now = utc_now_iso()
                # create migration owner
                mig_email = "migration@local.swot"
                mig_hash, mig_salt = hash_password(secrets.token_urlsafe(24))
                conn.execute(
                    "INSERT OR IGNORE INTO users (id, email, password_hash, password_salt, plan, created_at, last_login_at) VALUES (1, ?, ?, ?, 'free', ?, ?)",
                    (mig_email, mig_hash, mig_salt, now, now),
                )
                conn.execute("ALTER TABLE analyses RENAME TO analyses_legacy")
                conn.execute(
                    """
                    CREATE TABLE analyses (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        url TEXT NOT NULL,
                        domain TEXT NOT NULL,
                        overall INTEGER NOT NULL,
                        payload TEXT NOT NULL,
                        created_at TEXT NOT NULL,
                        FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                    )
                    """
                )
                conn.execute(
                    """
                    INSERT INTO analyses (id, user_id, url, domain, overall, payload, created_at)
                    SELECT id, 1, url, domain, overall, payload, created_at FROM analyses_legacy
                    """
                )
                conn.execute("DROP TABLE analyses_legacy")
        else:
            conn.execute(
                """
                CREATE TABLE analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    overall INTEGER NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
                )
                """
            )

        conn.execute("CREATE INDEX IF NOT EXISTS idx_analyses_user_created ON analyses(user_id, created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id)")
        conn.commit()
    finally:
        conn.close()


def db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


class SWOTHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def _send_json(self, status: int, payload: dict, cookies: list[str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if cookies:
            for cookie in cookies:
                self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > MAX_BODY_BYTES:
            raise ValueError(f"Request body too large (>{MAX_BODY_BYTES} bytes)")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON: {exc.msg}") from exc

    def _domain(self, url: str) -> str:
        return urlparse(url).hostname or url

    def _client_key(self) -> str:
        return self.client_address[0]

    def _enforce_rate_limit(self) -> tuple[bool, int]:
        now = time.time()
        key = self._client_key()
        bucket = RATE_BUCKETS.get(key, [])
        bucket = [ts for ts in bucket if now - ts < 60]
        if len(bucket) >= RATE_LIMIT_PER_MIN:
            RATE_BUCKETS[key] = bucket
            return False, 60
        bucket.append(now)
        RATE_BUCKETS[key] = bucket
        return True, 0

    def _auth_from_cookie(self) -> int | None:
        cookie_header = self.headers.get("Cookie")
        if not cookie_header:
            return None
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get(SESSION_COOKIE)
        if not morsel:
            return None
        checked = verify_session(morsel.value)
        if not checked:
            return None
        user_id, _exp = checked
        return user_id

    def _auth_from_api_key(self) -> int | None:
        raw = self.headers.get("X-API-Key", "").strip()
        if not raw:
            return None
        key_hash = hash_api_key(raw)
        conn = db_conn()
        try:
            row = conn.execute(
                "SELECT user_id FROM api_keys WHERE key_hash=? AND revoked_at IS NULL",
                (key_hash,),
            ).fetchone()
            if row:
                conn.execute("UPDATE api_keys SET last_used_at=? WHERE key_hash=?", (utc_now_iso(), key_hash))
                conn.commit()
                return int(row["user_id"])
            return None
        finally:
            conn.close()

    def _require_user(self) -> int | None:
        return self._auth_from_cookie() or self._auth_from_api_key()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/health":
            return self._send_json(HTTPStatus.OK, {"ok": True, "service": "swot-api", "time": utc_now_iso()})

        if path == "/api/auth/me":
            user_id = self._require_user()
            if not user_id:
                return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            conn = db_conn()
            try:
                row = conn.execute("SELECT id, email, plan, created_at FROM users WHERE id=?", (user_id,)).fetchone()
            finally:
                conn.close()
            if not row:
                return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid session"})
            return self._send_json(HTTPStatus.OK, {"user": dict(row)})

        if path == "/api/history":
            user_id = self._require_user()
            if not user_id:
                return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            query = parse_qs(parsed.query)
            try:
                limit = max(1, min(50, int((query.get("limit") or ["20"])[0])))
            except ValueError:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "limit must be an integer"})
            conn = db_conn()
            try:
                rows = conn.execute(
                    "SELECT id, url, domain, overall, created_at FROM analyses WHERE user_id=? ORDER BY id DESC LIMIT ?",
                    (user_id, limit),
                ).fetchall()
            finally:
                conn.close()
            return self._send_json(HTTPStatus.OK, {"items": [dict(r) for r in rows], "limit": limit})

        if path == "/api/keys":
            user_id = self._require_user()
            if not user_id:
                return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            conn = db_conn()
            try:
                rows = conn.execute(
                    "SELECT id, name, prefix, created_at, last_used_at, revoked_at FROM api_keys WHERE user_id=? ORDER BY id DESC",
                    (user_id,),
                ).fetchall()
            finally:
                conn.close()
            return self._send_json(HTTPStatus.OK, {"items": [dict(r) for r in rows]})

        if path.startswith("/api/history/"):
            user_id = self._require_user()
            if not user_id:
                return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            item_id = path.rsplit("/", 1)[-1]
            if not item_id.isdigit():
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid id"})
            conn = db_conn()
            try:
                row = conn.execute(
                    "SELECT id, url, domain, overall, payload, created_at FROM analyses WHERE id=? AND user_id=?",
                    (int(item_id), user_id),
                ).fetchone()
            finally:
                conn.close()
            if not row:
                return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            payload = dict(row)
            payload["payload"] = json.loads(payload["payload"])
            return self._send_json(HTTPStatus.OK, payload)

        return super().do_GET()

    def do_DELETE(self):
        path = urlparse(self.path).path

        if path.startswith("/api/history/"):
            user_id = self._require_user()
            if not user_id:
                return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            item_id = path.rsplit("/", 1)[-1]
            if not item_id.isdigit():
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid id"})
            conn = db_conn()
            try:
                cur = conn.execute("DELETE FROM analyses WHERE id=? AND user_id=?", (int(item_id), user_id))
                conn.commit()
            finally:
                conn.close()
            if cur.rowcount == 0:
                return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            return self._send_json(HTTPStatus.OK, {"deleted": int(item_id)})

        if path.startswith("/api/keys/"):
            user_id = self._require_user()
            if not user_id:
                return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            key_id = path.rsplit("/", 1)[-1]
            if not key_id.isdigit():
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid id"})
            conn = db_conn()
            try:
                cur = conn.execute(
                    "UPDATE api_keys SET revoked_at=? WHERE id=? AND user_id=? AND revoked_at IS NULL",
                    (utc_now_iso(), int(key_id), user_id),
                )
                conn.commit()
            finally:
                conn.close()
            if cur.rowcount == 0:
                return self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            return self._send_json(HTTPStatus.OK, {"revoked": int(key_id)})

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self):
        allowed, retry_after = self._enforce_rate_limit()
        if not allowed:
            return self._send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Rate limit exceeded", "retry_after": retry_after})

        path = urlparse(self.path).path
        try:
            body = self._read_json()
        except ValueError as exc:
            return self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

        if path == "/api/auth/register":
            email = (body.get("email") or "").strip().lower()
            password = body.get("password") or ""
            if "@" not in email or len(email) < 5:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Valid email required"})
            if len(password) < 8:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "Password must be at least 8 chars"})
            p_hash, p_salt = hash_password(password)
            conn = db_conn()
            try:
                now = utc_now_iso()
                cur = conn.execute(
                    "INSERT INTO users (email, password_hash, password_salt, created_at, last_login_at) VALUES (?, ?, ?, ?, ?)",
                    (email, p_hash, p_salt, now, now),
                )
                conn.commit()
                user_id = cur.lastrowid
            except sqlite3.IntegrityError:
                conn.close()
                return self._send_json(HTTPStatus.CONFLICT, {"error": "Email already registered"})
            finally:
                try:
                    conn.close()
                except Exception:
                    pass
            return self._send_json(
                HTTPStatus.CREATED,
                {"user": {"id": user_id, "email": email, "plan": "free", "created_at": now}},
                cookies=[build_session_cookie(user_id)],
            )

        if path == "/api/auth/login":
            email = (body.get("email") or "").strip().lower()
            password = body.get("password") or ""
            conn = db_conn()
            try:
                row = conn.execute(
                    "SELECT id, email, password_hash, password_salt, plan, created_at FROM users WHERE email=?",
                    (email,),
                ).fetchone()
                if not row:
                    return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credentials"})
                check_hash, _ = hash_password(password, row["password_salt"])
                if not hmac.compare_digest(check_hash, row["password_hash"]):
                    return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credentials"})
                conn.execute("UPDATE users SET last_login_at=? WHERE id=?", (utc_now_iso(), int(row["id"])))
                conn.commit()
                return self._send_json(
                    HTTPStatus.OK,
                    {
                        "user": {
                            "id": int(row["id"]),
                            "email": row["email"],
                            "plan": row["plan"],
                            "created_at": row["created_at"],
                        }
                    },
                    cookies=[build_session_cookie(int(row["id"]))],
                )
            finally:
                conn.close()

        if path == "/api/auth/logout":
            return self._send_json(HTTPStatus.OK, {"ok": True}, cookies=[clear_session_cookie()])

        if path == "/api/keys":
            user_id = self._require_user()
            if not user_id:
                return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            name = (body.get("name") or "default").strip()[:60]
            raw_key = f"swot_{secrets.token_urlsafe(32)}"
            key_hash = hash_api_key(raw_key)
            prefix = raw_key[:12]
            now = utc_now_iso()
            conn = db_conn()
            try:
                cur = conn.execute(
                    "INSERT INTO api_keys (user_id, name, key_hash, prefix, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, name, key_hash, prefix, now),
                )
                conn.commit()
                key_id = cur.lastrowid
            finally:
                conn.close()
            return self._send_json(HTTPStatus.CREATED, {"id": key_id, "name": name, "key": raw_key, "created_at": now})

        if path == "/api/fetch-html":
            raw_url = body.get("url") or ""
            try:
                url = normalize_target_url(raw_url)
            except ValueError as exc:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})

            try:
                req = Request(
                    url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (compatible; SWOT-Analyzer/1.0)",
                        "Accept": "text/html,application/xhtml+xml",
                    },
                )
                opener = build_opener(ProxyHandler({}))
                with opener.open(req, timeout=12) as resp:
                    html = resp.read().decode("utf-8", errors="replace")
                if len(html) < 100:
                    raise ValueError("Empty HTML response")
                return self._send_json(HTTPStatus.OK, {"html": html})
            except Exception as exc:
                return self._send_json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})

        if path == "/api/analyze":
            user_id = self._require_user()
            if not user_id:
                return self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required"})
            raw_url = body.get("url") or ""
            scores = body.get("scores")
            try:
                url = normalize_target_url(raw_url)
            except ValueError as exc:
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            if not isinstance(scores, dict):
                return self._send_json(HTTPStatus.BAD_REQUEST, {"error": "scores must be an object"})

            payload = {
                "url": url,
                "data": body.get("data") or {},
                "scores": scores,
                "insights": body.get("insights") or {},
                "version": 1,
            }
            overall = int(scores.get("overall") or 0)
            now = utc_now_iso()

            conn = db_conn()
            try:
                cur = conn.execute(
                    "INSERT INTO analyses (user_id, url, domain, overall, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, url, self._domain(url), overall, json.dumps(payload), now),
                )
                conn.commit()
                inserted_id = cur.lastrowid
            finally:
                conn.close()
            return self._send_json(HTTPStatus.CREATED, {"id": inserted_id, "created_at": now})

        self._send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})


def run() -> None:
    init_db()
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "4173"))
    httpd = ThreadingHTTPServer((host, port), SWOTHandler)
    print(f"SWOT server running on http://{host}:{port}")
    if APP_SECRET == "dev-only-change-me":
        print("[WARN] APP_SECRET is using default value. Set APP_SECRET in production.")
    httpd.serve_forever()


if __name__ == "__main__":
    run()
