# Authentication and Authorization

TraceLayer v2 replaced v1's single shared API token with per-user accounts, server-side sessions and
role-based access control. Everything below is enforced by the API. The UI only hides controls a user
cannot use, and `tests/test_rbac_matrix.py` proves the server refuses them anyway.

## Accounts

| Feature | Implementation |
|---|---|
| Password hashing | **Argon2id** via `argon2-cffi` (reference C implementation), RFC 9106 parameters: t=3, m=64 MiB, p=4. Hashes are upgraded transparently at login if parameters change. |
| Password policy | 12–256 characters, not a common password, not containing the email name. Passphrases are encouraged. |
| First administrator | `make create-admin` (prompts; the password is never a CLI argument), or the one-time `TRACELAYER_BOOTSTRAP_ADMIN_*` env vars, which apply only while no user exists, force a password change at first login, and are refused in production. |
| Registration | `invite` by default: admin-issued single-use links that expire in 7 days and are optionally bound to an email. `disabled` and `open` (viewer role, local labs only, refused in production) are available. |
| Account status | `active` / `disabled`. Disabling, or changing a role, revokes all of that user's sessions immediately. |
| Guard rails | The last active administrator cannot be demoted or disabled; administrators cannot remove their own admin access. |
| Recovery (no email needed) | An administrator issues a **one-time recovery code** (256-bit, 60-minute lifetime, only its SHA-256 stored, shown once) and hands it over out of band. Redeeming it sets a new password and revokes every session. Break-glass on the host: `tracelayer reset-password --email …`. |
| Login history | Every attempt (success or failure, with reason, IP, user agent) is in `login_events`, visible to the user and to administrators. |

## Sessions

| Property | Value |
|---|---|
| Token | 256-bit random (`secrets.token_urlsafe(32)`), in an **HttpOnly** cookie. JavaScript never sees it; nothing goes in `localStorage`. |
| Storage | Server-side `user_sessions` table holding only **SHA-256(token)**, so a database read does not yield usable sessions. |
| Cookie flags | `HttpOnly; SameSite=Lax; Path=/`. With `TRACELAYER_COOKIE_SECURE=true` the cookie becomes `__Host-tl_session` with `Secure`. Production refuses to start without it. |
| Lifetime | 8 h sliding inactivity timeout (`last_seen_at`, touched at most once a minute) **and** a 7-day absolute cap. |
| Rotation | Every login creates a new session and revokes any session the browser presented (session fixation). A password change revokes all sessions and issues a fresh one. |
| Revocation | Per session (Account → Active sessions), "sign out all others", admin "sign out everywhere", and automatically on role or status change. |
| Persistence across reloads | The UI calls `/api/auth/me` on load; the cookie keeps working until it expires or is revoked (Playwright test: reload stays signed in). |
| Expiry UX | Any API call that finds the session expired or revoked switches the app to a "Your session expired" / "You were signed out" screen. |

### CSRF

Each session has its own CSRF token (synchronizer-token pattern). `/api/auth/me` returns it, the UI
keeps it in memory, and every POST/PUT/PATCH/DELETE must send it in `X-CSRF-Token`, compared in
constant time. A cross-site page can make a browser send the cookie but cannot read the token.
`SameSite=Lax` and an `Origin` check (allowed: own origin and `TRACELAYER_CORS_ORIGINS`) add two more
layers. Login is JSON-only, so a cross-site HTML form cannot submit it.

### Enumeration and brute force

Unknown email, wrong password and disabled account return the **same** 401 body. The unknown-email
path still runs an Argon2 verification against a dummy hash, so timing does not reveal which case
occurred. Rate limits use sliding windows: login is limited to 30 per IP and 10 per account per 15
minutes, and registration, recovery and password change to 10 per IP per 15 minutes. nginx adds
10 requests/minute on `/api/auth/` in Docker. Accounts are deliberately **not** locked, because lockout
lets anyone deny service to a known user. Limitation: the limiter is in-process (single worker).

## Roles and permissions

Routes depend on **permissions**; roles are bundles (`app/auth/rbac.py`).

| Permission | Viewer | Analyst | Admin |
|---|:-:|:-:|:-:|
| Read events, detections, investigations, analyses, metrics, datasets | ✓ | ✓ | ✓ |
| Own account, sessions, saved filters | ✓ | ✓ | ✓ |
| Update cases (status, priority, assignment), comments/notes, pin evidence | | ✓ | ✓ |
| Generate analyses, review claims, approve analyses, validator playground | | ✓ | ✓ |
| Export reports and evidence bundles; re-run detection | | ✓ | ✓ |
| Manage users, invitations, recovery codes, settings; read the global audit log | | | ✓ |
| Ingest data, import datasets, generate synthetic data | | | ✓ |
| Run evaluation and benchmarks, full ledger verification, change any case | | | ✓ |

### Horizontal privilege escalation and IDOR

| Object | Rule |
|---|---|
| Cases | Analysts may change a case that is unassigned or assigned to them; taking or reassigning someone else's case needs an administrator. Only the designated reviewer (not the assignee) can complete or return a review. |
| Comments and notes | Only the author can edit or delete (administrators included: history is personal). |
| Sessions | Revoking another user's session id returns 404, indistinguishable from a missing id. |
| Saved filters | Private; another user's filter id returns 404. |

### How this is tested

- `test_rbac_matrix.py` enumerates **every registered route** (79) and asserts: exactly 5 public
  routes, 401 everywhere else without a session, and 403 for every role lacking the permission
  (20 denials for analysts, 33 for viewers). A new route without a permission dependency fails CI.
- The same file replays forged viewer requests for each hidden write action.
- `test_auth.py` (13 tests) covers cookie flags, uniform failures, idle and absolute expiry, fixation,
  CSRF and Origin, rate limits, rotation on password change, the IDOR guards, admin guard rails,
  invitations, recovery and production configuration checks.
- Playwright (`frontend/e2e/`) checks the real browser flow: forced password change, reload
  persistence, HttpOnly cookie, revocation from another browser, and a viewer's forged request getting 403.

## Local HTTP development

Cookies are not `Secure` by default (`TRACELAYER_COOKIE_SECURE=false`, `TRACELAYER_ENV=development`),
because `http://localhost` cannot carry Secure cookies in every browser. **Any deployment reachable by
other people must use HTTPS** with `TRACELAYER_ENV=production`, which enforces Secure cookies,
`__Host-` cookie naming and HSTS, and refuses open registration, exposed API docs or a lingering
bootstrap password.

## What was removed, and why

The v1 `TRACELAYER_API_TOKEN` and the `X-Analyst` header are gone. A shared token is a credential that
bypasses roles by design, and a client-supplied analyst name made the hash-chained audit log faithfully
record forged identities (audit findings C2–C4). Automation uses the CLI on the host.

## Not implemented (next steps)

MFA (TOTP or WebAuthn), SSO/OIDC, a shared rate-limit store for multiple workers, and
breached-password checks against a local k-anonymity list.
