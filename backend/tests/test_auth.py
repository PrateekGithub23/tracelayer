"""Authentication, sessions, CSRF, rate limiting, account management and recovery."""

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.auth.passwords import digest
from app.db import session_scope
from app.main import create_app
from app.models import LoginEvent, User, UserSession, utcnow
from tests.conftest import PASSWORDS, login, make_user

ADMIN, ANALYST = "admin@example.test", "analyst@example.test"


def _fresh(app_factory) -> TestClient:  # type: ignore[no-untyped-def]
    return TestClient(app_factory())


def test_login_sets_httponly_cookie_and_me_works(anon_client: TestClient) -> None:
    make_user("analyst")
    r = anon_client.post("/api/auth/login", json={"email": "Analyst@Example.TEST ", "password": PASSWORDS["analyst"]})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie and "Path=/" in cookie
    secret = anon_client.cookies.get("tl_session")
    assert secret and secret not in r.text  # the bearer secret is never in a JS-readable body
    me = anon_client.get("/api/auth/me").json()
    assert me["user"]["email"] == ANALYST and me["user"]["role"] == "analyst"
    assert "investigations:write" in me["permissions"] and "users:manage" not in me["permissions"]
    with session_scope() as s:  # only the hash is stored
        assert s.scalar(select(UserSession.token_hash)) == digest(secret)
        assert s.scalar(select(User.password_hash)).startswith("$argon2id$")


def test_failures_are_uniform(anon_client: TestClient) -> None:
    make_user("analyst")
    disabled = make_user("viewer")
    with session_scope() as s:
        s.execute(update(User).where(User.id == disabled).values(status="disabled"))
    bodies = {
        anon_client.post("/api/auth/login", json={"email": e, "password": p}).text
        for e, p in ((ANALYST, "wrong-password-123"), ("nobody@example.test", "whatever-1234"),
                     ("viewer@example.test", PASSWORDS["viewer"]))
    }  # fmt: skip
    assert len(bodies) == 1 and "invalid email or password" in bodies.pop()
    with session_scope() as s:
        reasons = sorted(s.scalars(select(LoginEvent.reason)))
    assert reasons == ["account_disabled", "bad_password", "unknown_user"]


def test_session_survives_refresh_and_expires(anon_client: TestClient, app_factory) -> None:  # type: ignore[no-untyped-def]
    make_user("viewer")
    login(anon_client, "viewer@example.test", PASSWORDS["viewer"])
    secret = anon_client.cookies.get("tl_session")
    # A "browser refresh" is a brand-new HTTP client presenting the same cookie.
    with _fresh(app_factory) as other:
        other.cookies.set("tl_session", secret)
        assert other.get("/api/auth/me").status_code == 200
        with session_scope() as s:  # idle timeout
            s.execute(update(UserSession).values(last_seen_at=utcnow() - timedelta(hours=9)))
        r = other.get("/api/auth/me")
        assert r.status_code == 401 and r.json()["detail"]["reason"] == "expired"
    login(anon_client, "viewer@example.test", PASSWORDS["viewer"])
    with session_scope() as s:  # absolute lifetime, even if active
        s.execute(update(UserSession).where(UserSession.revoked_at.is_(None))
                  .values(expires_at=utcnow() - timedelta(seconds=1)))  # fmt: skip
    assert anon_client.get("/api/auth/me").json()["detail"]["reason"] == "expired"


def test_logout_and_fixation(anon_client: TestClient, app_factory) -> None:  # type: ignore[no-untyped-def]
    make_user("viewer")
    login(anon_client, "viewer@example.test", PASSWORDS["viewer"])
    first = anon_client.cookies.get("tl_session")
    login(anon_client, "viewer@example.test", PASSWORDS["viewer"])  # login with an existing cookie
    second = anon_client.cookies.get("tl_session")
    assert first != second
    with _fresh(app_factory) as c:
        c.cookies.set("tl_session", first)
        assert c.get("/api/auth/me").json()["detail"]["reason"] == "revoked"
    assert anon_client.post("/api/auth/logout").status_code == 200
    with _fresh(app_factory) as c:
        c.cookies.set("tl_session", second)
        assert c.get("/api/auth/me").status_code == 401


def test_csrf_and_origin_enforced(admin_client: TestClient) -> None:
    token = admin_client.headers.pop("X-CSRF-Token")
    assert admin_client.get("/api/auth/me").status_code == 200  # safe methods need no token
    assert admin_client.post("/api/pipeline/runs").status_code == 403
    assert admin_client.post("/api/pipeline/runs", headers={"X-CSRF-Token": "forged"}).status_code == 403
    assert admin_client.post("/api/pipeline/runs", headers={"X-CSRF-Token": token}).status_code == 200
    evil = {"X-CSRF-Token": token, "Origin": "https://evil.example"}
    assert admin_client.post("/api/pipeline/runs", headers=evil).status_code == 403


def test_login_rate_limit(anon_client: TestClient) -> None:
    make_user("analyst")
    codes = [anon_client.post("/api/auth/login", json={"email": ANALYST, "password": "nope-nope-nope"}).status_code
             for _ in range(11)]  # fmt: skip
    assert codes[:10] == [401] * 10 and codes[10] == 429
    # Even the right password is refused while limited: the attacker learns nothing from timing the lockout.
    r = anon_client.post("/api/auth/login", json={"email": ANALYST, "password": PASSWORDS["analyst"]})
    assert r.status_code == 429 and "retry-after" in r.headers


def test_password_change_rotates_and_revokes(anon_client: TestClient, app_factory) -> None:  # type: ignore[no-untyped-def]
    make_user("analyst")
    with _fresh(app_factory) as laptop:
        login(laptop, ANALYST, PASSWORDS["analyst"])
        login(anon_client, ANALYST, PASSWORDS["analyst"])
        old_cookie = anon_client.cookies.get("tl_session")
        bad = anon_client.post("/api/auth/password", json={"current_password": "wrong", "new_password": "x"})
        assert bad.status_code == 400
        weak = anon_client.post("/api/auth/password", json={"current_password": PASSWORDS["analyst"],
                                                            "new_password": "short"})  # fmt: skip
        assert weak.status_code == 422
        new = "Tundra-saffron-6612"
        ok = anon_client.post(
            "/api/auth/password", json={"current_password": PASSWORDS["analyst"], "new_password": new}
        )
        assert ok.status_code == 200
        anon_client.headers["X-CSRF-Token"] = ok.json()["csrf_token"]
        assert anon_client.cookies.get("tl_session") != old_cookie  # rotated
        assert anon_client.get("/api/auth/me").status_code == 200
        assert laptop.get("/api/auth/me").status_code == 401  # other sessions revoked
    assert (
        anon_client.post("/api/auth/login", json={"email": ANALYST, "password": PASSWORDS["analyst"]}).status_code
        == 401
    )


def test_sessions_page_and_idor(anon_client: TestClient, app_factory) -> None:  # type: ignore[no-untyped-def]
    make_user("analyst")
    make_user("viewer")
    with _fresh(app_factory) as victim:
        login(victim, "viewer@example.test", PASSWORDS["viewer"])
        victim_session = victim.get("/api/auth/me").json()["session"]["id"]
        login(anon_client, ANALYST, PASSWORDS["analyst"])
        mine = anon_client.get("/api/auth/sessions").json()
        assert [s["current"] for s in mine] == [True] and victim_session not in {s["id"] for s in mine}
        # Revoking someone else's session id is indistinguishable from a missing one.
        assert anon_client.delete(f"/api/auth/sessions/{victim_session}").status_code == 404
        assert victim.get("/api/auth/me").status_code == 200
        hist = anon_client.get("/api/auth/login-history").json()
        assert all(h["success"] for h in hist) and len(hist) == 1


def test_admin_user_management_guards(admin_client: TestClient, app_factory) -> None:  # type: ignore[no-untyped-def]
    admin_id = admin_client.get("/api/auth/me").json()["user"]["id"]
    assert admin_client.patch(f"/api/admin/users/{admin_id}", json={"role": "viewer"}).status_code == 409
    assert admin_client.patch(f"/api/admin/users/{admin_id}", json={"status": "disabled"}).status_code == 409
    r = admin_client.post("/api/admin/users", json={"email": "new@example.test", "role": "analyst",
                                                    "password": "Copper-meadow-3310"})  # fmt: skip
    assert r.status_code == 201 and r.json()["must_change_password"] is True
    uid = r.json()["id"]
    with _fresh(app_factory) as c:
        login(c, "new@example.test", "Copper-meadow-3310")
        # Must change the password before doing anything else.
        assert c.get("/api/investigations").json()["detail"]["reason"] == "must_change_password"
        ok = c.post("/api/auth/password", json={"current_password": "Copper-meadow-3310",
                                                "new_password": "Juniper-quartz-8841"})  # fmt: skip
        c.headers["X-CSRF-Token"] = ok.json()["csrf_token"]
        assert c.get("/api/investigations").status_code == 200
        # Downgrading the role revokes the session immediately (no waiting for expiry).
        assert admin_client.patch(f"/api/admin/users/{uid}", json={"role": "viewer"}).status_code == 200
        assert c.get("/api/auth/me").status_code == 401
        login(c, "new@example.test", "Juniper-quartz-8841")
        assert c.get("/api/auth/me").json()["user"]["role"] == "viewer"
        assert admin_client.patch(f"/api/admin/users/{uid}", json={"status": "disabled"}).status_code == 200
        assert c.get("/api/auth/me").status_code == 401


def test_invitation_registration(admin_client: TestClient, anon_client: TestClient) -> None:
    inv = admin_client.post("/api/admin/invitations", json={"email": "invitee@example.test", "role": "analyst"}).json()
    body = {"invite_token": inv["token"], "email": "invitee@example.test", "display_name": "Invitee",
            "password": "Sparrow-helium-2207"}  # fmt: skip
    assert anon_client.post("/api/auth/register", json={**body, "email": "other@example.test"}).status_code == 400
    r = anon_client.post("/api/auth/register", json=body)
    assert r.status_code == 201 and r.json()["user"]["role"] == "analyst"
    assert anon_client.post("/api/auth/register", json=body).status_code == 400  # single use
    assert anon_client.post("/api/auth/register", json={**body, "invite_token": "guess"}).status_code == 400
    admin_client.patch("/api/admin/settings", json={"registration_mode": "disabled"})
    assert anon_client.post("/api/auth/register", json=body).status_code == 403
    assert admin_client.get("/api/admin/invitations").json()[0]["state"] == "used"


def test_admin_recovery_code(admin_client: TestClient, anon_client: TestClient) -> None:
    uid = make_user("analyst")
    login(anon_client, ANALYST, PASSWORDS["analyst"])
    code = admin_client.post(f"/api/admin/users/{uid}/recovery-code").json()["code"]
    new = "Falcon-ember-7734"
    assert (
        anon_client.post(
            "/api/auth/recover", json={"email": ANALYST, "code": "x" * 20, "new_password": new}
        ).status_code
        == 400
    )
    assert (
        anon_client.post("/api/auth/recover", json={"email": ANALYST, "code": code, "new_password": new}).status_code
        == 200
    )
    assert anon_client.get("/api/auth/me").status_code == 401  # existing sessions revoked
    assert (
        anon_client.post("/api/auth/recover", json={"email": ANALYST, "code": code, "new_password": new}).status_code
        == 400
    )
    login(anon_client, ANALYST, new)


def test_validation_errors_do_not_echo_input(anon_client: TestClient) -> None:
    r = anon_client.post("/api/auth/login", json={"email": "a@b.cd", "password": "p" * 300})
    assert r.status_code == 422 and "ppppp" not in r.text


def test_production_refuses_insecure_config(db_url: str, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import pytest

    from app.config import get_settings
    from app.main import InsecureConfiguration

    monkeypatch.setenv("TRACELAYER_ENV", "production")
    get_settings.cache_clear()
    try:
        with pytest.raises(InsecureConfiguration, match="COOKIE_SECURE"), TestClient(create_app()):
            pass
        monkeypatch.setenv("TRACELAYER_COOKIE_SECURE", "true")
        get_settings.cache_clear()
        with TestClient(create_app(), base_url="https://testserver") as c:
            make_user("viewer")
            r = c.post("/api/auth/login", json={"email": "viewer@example.test", "password": PASSWORDS["viewer"]})
            assert "__Host-tl_session=" in r.headers["set-cookie"] and "Secure" in r.headers["set-cookie"]
            assert "strict-transport-security" in r.headers
    finally:
        get_settings.cache_clear()


def test_activity_history_and_failed_login_visibility(admin_client: TestClient, anon_client: TestClient) -> None:
    uid = make_user("analyst")
    anon_client.post("/api/auth/login", json={"email": ANALYST, "password": "wrong-password-xx"})
    login(anon_client, ANALYST, PASSWORDS["analyst"])
    mine = anon_client.get("/api/auth/activity").json()
    assert [a["action"] for a in mine] == ["auth.login"]  # only this user's own audited actions
    assert anon_client.get(f"/api/admin/users/{uid}/activity").status_code == 403
    users = {u["email"]: u for u in admin_client.get("/api/admin/users").json()}
    assert users[ANALYST]["failed_logins_24h"] == 1
    assert admin_client.get(f"/api/admin/users/{uid}/activity").json()[0]["action"] == "auth.login"
    assert anon_client.get("/api/auth/me").json()["session"]["idle_minutes"] == 480
