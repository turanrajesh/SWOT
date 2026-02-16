# SWOT Analyzer SaaS (Frontend + Production-Oriented Backend)

## What is implemented

- Multi-user SaaS baseline with **account registration/login/logout**.
- Secure session cookie auth (`HttpOnly`, `SameSite=Lax`) and optional API-key auth.
- Tenant-safe data isolation (each user sees only their own analyses/history).
- SQLite persistence with WAL mode, indexed query paths, and relational schema.
- Rate limiting, request size limit, URL validation, and hardened response headers.
- Backend-first HTML fetch with frontend proxy fallback.
- Complete SWOT UI workflow: loading pipeline, radar scoring, SWOT cards, detailed metrics, export tools.

## Run locally

```bash
export APP_SECRET="change-this-in-prod"
python3 server.py
```

Open: `http://127.0.0.1:4173/swot.html`

## Environment variables

- `APP_SECRET` (required in production): signing key for auth session cookies.
- `PORT` (default `4173`).
- `HOST` (default `0.0.0.0`).
- `MAX_BODY_BYTES` (default `1000000`).
- `SESSION_TTL_SECONDS` (default `604800`).
- `RATE_LIMIT_PER_MIN` (default `120`).

## API endpoints

### Auth
- `POST /api/auth/register` `{ email, password }`
- `POST /api/auth/login` `{ email, password }`
- `POST /api/auth/logout`
- `GET /api/auth/me`

### API keys
- `POST /api/keys` `{ name }`
- `GET /api/keys`
- `DELETE /api/keys/{id}`

### SWOT
- `GET /api/health`
- `POST /api/fetch-html` `{ url }`
- `POST /api/analyze` `{ url, data, scores, insights }`
- `GET /api/history?limit=8`
- `GET /api/history/{id}`
- `DELETE /api/history/{id}`

## Database

SQLite file: `swot.db` (auto-created).

Tables:
- `users`
- `api_keys`
- `analyses`

All SWOT history and records are user-scoped for multi-tenant safety.

## Production recommendations

- Replace SQLite with PostgreSQL for horizontal scale.
- Run behind a reverse proxy (TLS termination, WAF, gzip/brotli).
- Set strict `APP_SECRET`, and rotate it regularly.
- Add centralized logs/metrics/traces and managed backups.
- Add CI tests for API routes + browser E2E tests.
