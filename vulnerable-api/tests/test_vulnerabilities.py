"""
Test suite proving that VulnBank's intentional vulnerabilities are real and verifiable.
"""

import pytest
from app.config import settings


def test_health_check(client):
    """Test health check and root endpoints."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["secure_mode"] is False

    response = client.get("/")
    assert response.status_code == 200
    assert "endpoints" in response.json()


def test_login_and_jwt_weakness(client):
    """Test login works and JWT contains intentional weaknesses (no exp, sensitive claims)."""
    response = client.post("/api/v1/auth/login", json={"username": "alice", "password": "password123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    token = data["access_token"]

    # Decode without verifying signature to inspect claims directly
    import jwt
    unverified = jwt.decode(token, options={"verify_signature": False})
    assert "sub" in unverified
    assert unverified["sub"] == "1"
    # In vulnerable mode: email and api_key are exposed in claims, and exp is missing
    assert "email" in unverified
    assert "api_key" in unverified
    assert "exp" not in unverified


def test_bola_idor_users(client):
    """
    Test BOLA / IDOR on /users/{id}.
    Alice (User ID 1) accesses Bob (User ID 2) without restriction.
    """
    # 1. Login as Alice
    login_res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "password123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Access Alice's own data
    alice_res = client.get("/api/v1/users/1", headers=headers)
    assert alice_res.status_code == 200
    assert alice_res.json()["username"] == "alice"

    # 3. Access Bob's data using Alice's token
    bob_res = client.get("/api/v1/users/2", headers=headers)
    assert bob_res.status_code == 200
    assert bob_res.json()["username"] == "bob"
    assert bob_res.json()["email"] == "bob@vulnbank.com"


def test_bola_idor_accounts(client):
    """
    Test BOLA / IDOR on /accounts/{id} and transactions.
    Alice accesses Bob's account (id=102) and transactions.
    """
    login_res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "password123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Access Bob's account
    acc_res = client.get("/api/v1/accounts/102", headers=headers)
    assert acc_res.status_code == 200
    assert acc_res.json()["account_number"] == "ACC-002-BOB"
    assert acc_res.json()["user_id"] == 2

    # Access Bob's transactions
    tx_res = client.get("/api/v1/accounts/102/transactions", headers=headers)
    assert tx_res.status_code == 200
    assert isinstance(tx_res.json(), list)
    assert len(tx_res.json()) > 0


def test_missing_authentication_admin_users(client):
    """
    Test missing authentication on /api/v1/admin/users.
    Unauthenticated request succeeds and returns full user directory.
    """
    response = client.get("/api/v1/admin/users")
    assert response.status_code == 200
    users = response.json()
    assert isinstance(users, list)
    assert len(users) >= 3
    usernames = [u["username"] for u in users]
    assert "alice" in usernames
    assert "bob" in usernames
    assert "admin" in usernames


def test_sensitive_data_exposure_profile(client):
    """
    Test sensitive data exposure on /api/v1/profile.
    Response includes password_hash and api_key.
    """
    login_res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "password123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    res = client.get("/api/v1/profile", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "password_hash" in data
    assert data["password_hash"] is not None
    assert "api_key" in data
    assert data["api_key"] == "ak_alice_secret_key_12345"


def test_sql_injection_search(client):
    """
    Test SQL injection on /api/v1/search?q=.
    Payload `' OR '1'='1` returns all users.
    Single quote payload `'` causes a syntax error disclosure.
    """
    # 1. Normal query
    normal_res = client.get("/api/v1/search?q=alice")
    assert normal_res.status_code == 200
    assert normal_res.json()["count"] == 1

    # 2. SQLi tautology payload returns all records
    sqli_res = client.get("/api/v1/search?q=' OR '1'='1")
    assert sqli_res.status_code == 200
    assert sqli_res.json()["count"] >= 3

    # 3. Error-inducing payload exposes database error
    error_res = client.get("/api/v1/search?q='")
    assert error_res.status_code == 200
    assert "error" in error_res.json()
    err_text = error_res.json()["error"].lower()
    assert any(sig in err_text for sig in ["syntax error", "unclosed", "unrecognized token", "operationalerror"])


def test_missing_security_headers(client):
    """
    Test missing security headers in vulnerable mode.
    Key headers like CSP, HSTS, X-Frame-Options must be absent.
    """
    res = client.get("/health")
    assert "Content-Security-Policy" not in res.headers
    assert "Strict-Transport-Security" not in res.headers
    assert "X-Frame-Options" not in res.headers
    assert "X-Content-Type-Options" not in res.headers


def test_secure_mode_remediation(client):
    """
    Test that when settings.secure_mode=True:
    1. BOLA is blocked (403)
    2. Admin endpoint requires auth (401)
    3. Sensitive fields are removed from profile
    4. Security headers are present
    """
    settings.secure_mode = True
    try:
        # 1. Login as Alice
        login_res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "password123"})
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # BOLA on user profile should now return 403
        bola_user_res = client.get("/api/v1/users/2", headers=headers)
        assert bola_user_res.status_code == 403

        # BOLA on account should now return 403
        bola_acc_res = client.get("/api/v1/accounts/102", headers=headers)
        assert bola_acc_res.status_code == 403

        # Admin route without auth should now return 401
        admin_res = client.get("/api/v1/admin/users")
        assert admin_res.status_code == 401

        # Profile should no longer expose password_hash or api_key
        prof_res = client.get("/api/v1/profile", headers=headers)
        assert prof_res.status_code == 200
        assert "password_hash" not in prof_res.json()
        assert "api_key" not in prof_res.json()

        # Security headers should now be present
        health_res = client.get("/health")
        assert "Content-Security-Policy" in health_res.headers
        assert "X-Frame-Options" in health_res.headers
        assert "X-Content-Type-Options" in health_res.headers
    finally:
        settings.secure_mode = False


def test_change_password_and_rate_limiting(client):
    """
    Test password change functionality and rate limiting behavior.
    In vulnerable mode: unlimited attempts allowed.
    In secure mode: throttled after 5 requests (returns HTTP 429).
    """
    login_res = client.post("/api/v1/auth/login", json={"username": "alice", "password": "password123"})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Wrong current password fails
    wrong_res = client.post(
        "/api/v1/change-password",
        json={"current_password": "wrongpassword", "new_password": "newpassword123"},
        headers=headers,
    )
    assert wrong_res.status_code == 400

    # Successful password change
    change_res = client.post(
        "/api/v1/change-password",
        json={"current_password": "password123", "new_password": "newpassword123"},
        headers=headers,
    )
    assert change_res.status_code == 200
    assert change_res.json()["message"] == "Password changed successfully"

    # Revert password back
    revert_res = client.post(
        "/api/v1/change-password",
        json={"current_password": "newpassword123", "new_password": "password123"},
        headers=headers,
    )
    assert revert_res.status_code == 200

    # Test rate limiting enforcement in secure mode
    settings.secure_mode = True
    try:
        from app.routes.password import _rate_limit_store
        _rate_limit_store.clear()

        statuses = []
        for _ in range(7):
            r = client.post(
                "/api/v1/change-password",
                json={"current_password": "probe", "new_password": "probe"},
                headers=headers,
            )
            statuses.append(r.status_code)

        # First 5 attempts processed (400 bad current password), 6th and 7th return 429
        assert 429 in statuses
        assert statuses[-1] == 429
    finally:
        settings.secure_mode = False

