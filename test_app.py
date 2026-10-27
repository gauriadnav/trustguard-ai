"""
TrustGuard AI — Full-Stack Integration Verification Test
Tests Flask endpoints, database transactions, authentication flows,
scam analysis API, guest vs authenticated scan isolation, and dashboard statistics.
"""

import sys
import json
from app import app
from db import execute_query, fetch_one, fetch_all


def run_integration_tests():
    print("=" * 65)
    print(" TrustGuard AI — Full-Stack Application Verification Suite")
    print("=" * 65)

    client = app.test_client()
    passed = 0
    total = 0

    def assert_test(name, condition, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"[PASS] {name} {details}")
            return True
        else:
            print(f"[FAIL] {name} {details}")
            return False

    # --- Test 1: Homepage Rendering ---
    res = client.get("/")
    assert_test(
        "1. GET / (Homepage)",
        res.status_code == 200 and b"TrustGuard" in res.data and b"Scanner" in res.data,
        f"(Status: {res.status_code})"
    )

    # --- Test 2: Unauthenticated / Guest Scan ---
    # Guest scans must be allowed and recorded with user_id = NULL
    scan_payload = {
        "content": "URGENT: Your PayPal account has been locked. Verify PIN immediately at http://192.168.1.1/login",
        "scan_type": "email"
    }
    res = client.post("/api/scan", json=scan_payload)
    data = res.get_json() or {}
    guest_scan_ok = (
        res.status_code == 200 and
        data.get("success") is True and
        data.get("data", {}).get("risk_score", 0) >= 70 and
        data.get("data", {}).get("is_authenticated") is False
    )
    assert_test(
        "2. POST /api/scan (Guest Scan)",
        guest_scan_ok,
        f"(Score: {data.get('data', {}).get('risk_score')}, Auth: {data.get('data', {}).get('is_authenticated')})"
    )

    guest_scan_id = data.get("data", {}).get("scan_id")
    # Verify DB record has user_id = NULL
    if guest_scan_id:
        db_row = fetch_one("SELECT user_id, risk_score, risk_level FROM scans WHERE id = %s", (guest_scan_id,))
        assert_test(
            "3. Database Guest Scan Isolation",
            db_row is not None and db_row["user_id"] is None,
            f"(DB user_id: {db_row['user_id'] if db_row else 'None'})"
        )

    # --- Test 3: Input Validation on Scan Endpoint ---
    res_empty = client.post("/api/scan", json={"content": "   ", "scan_type": "text"})
    assert_test(
        "4. POST /api/scan (Empty Content Validation)",
        res_empty.status_code == 400 and res_empty.get_json().get("success") is False,
        f"(Status: {res_empty.status_code})"
    )

    # --- Test 4: User Registration Flow ---
    test_username = "test_sec_user_2026"
    test_email = "sec_test_2026@example.com"
    test_password = "Password@12345"

    # Clean up prior test user if exists
    prior_user = fetch_one("SELECT id FROM users WHERE username = %s OR email = %s", (test_username, test_email))
    if prior_user:
        execute_query("DELETE FROM scans WHERE user_id = %s", (prior_user["id"],), commit=True)
        execute_query("DELETE FROM users WHERE id = %s", (prior_user["id"],), commit=True)

    reg_payload = {
        "username": test_username,
        "email": test_email,
        "password": test_password,
        "confirm_password": test_password
    }
    res_reg = client.post("/register", data=reg_payload, follow_redirects=False)
    assert_test(
        "5. POST /register (User Account Creation)",
        res_reg.status_code == 302 and "/dashboard" in res_reg.headers.get("Location", ""),
        f"(Redirected to: {res_reg.headers.get('Location')})"
    )

    # Verify password was hashed (never stored in plaintext)
    user_row = fetch_one("SELECT id, username, password_hash FROM users WHERE username = %s", (test_username,))
    assert_test(
        "6. Password Security (Hashed Storage)",
        user_row is not None and user_row["password_hash"] != test_password and user_row["password_hash"].startswith(("scrypt:", "pbkdf2:")),
        f"(Hash prefix: {user_row['password_hash'][:15] if user_row else 'None'})"
    )

    # --- Test 5: Authenticated User Scan Attribution ---
    # With this active session, scan should be attributed to user_row['id']
    auth_scan_payload = {
        "content": "Hi Team, the project presentation has been rescheduled to Thursday at 10 AM.",
        "scan_type": "text"
    }
    res_auth_scan = client.post("/api/scan", json=auth_scan_payload)
    auth_data = res_auth_scan.get_json() or {}
    auth_scan_ok = (
        res_auth_scan.status_code == 200 and
        auth_data.get("data", {}).get("is_authenticated") is True
    )
    assert_test(
        "7. POST /api/scan (Authenticated Scan Attribution)",
        auth_scan_ok,
        f"(Auth Status: {auth_data.get('data', {}).get('is_authenticated')})"
    )

    auth_scan_id = auth_data.get("data", {}).get("scan_id")
    if auth_scan_id and user_row:
        db_auth_row = fetch_one("SELECT user_id, risk_score FROM scans WHERE id = %s", (auth_scan_id,))
        assert_test(
            "8. Database Authenticated Scan Record",
            db_auth_row is not None and db_auth_row["user_id"] == user_row["id"],
            f"(Linked to User ID: {db_auth_row['user_id'] if db_auth_row else 'None'})"
        )

    # --- Test 6: Dashboard Route Access (Authenticated) ---
    res_dash = client.get("/dashboard")
    assert_test(
        "9. GET /dashboard (Authenticated View)",
        res_dash.status_code == 200 and b"Security Dashboard" in res_dash.data and test_username.encode() in res_dash.data,
        f"(Status: {res_dash.status_code})"
    )

    # --- Test 7: Dashboard Stats API ---
    res_stats = client.get("/api/dashboard/stats")
    stats_json = res_stats.get_json() or {}
    assert_test(
        "10. GET /api/dashboard/stats (Chart.js Metrics)",
        res_stats.status_code == 200 and stats_json.get("success") is True and "risk_breakdown" in stats_json,
        f"(Total in Breakdown: {sum(stats_json.get('risk_breakdown', {}).values())})"
    )

    # --- Test 8: Scan Detail Fetch ---
    if auth_scan_id:
        res_detail = client.get(f"/api/scan/{auth_scan_id}")
        detail_json = res_detail.get_json() or {}
        assert_test(
            "11. GET /api/scan/<id> (Detail Modal API)",
            res_detail.status_code == 200 and detail_json.get("success") is True,
            f"(Fetched Scan #{auth_scan_id})"
        )

    # --- Test 9: Logout & Route Protection ---
    res_logout = client.get("/logout", follow_redirects=False)
    assert_test(
        "12. GET /logout (Session Invalidation)",
        res_logout.status_code == 302 and "/login" in res_logout.headers.get("Location", ""),
        f"(Redirected to: {res_logout.headers.get('Location')})"
    )

    # Protected route should redirect to login when logged out
    res_dash_anon = client.get("/dashboard", follow_redirects=False)
    assert_test(
        "13. Route Protection (Unauthenticated /dashboard redirect)",
        res_dash_anon.status_code == 302 and "/login" in res_dash_anon.headers.get("Location", ""),
        f"(Protected redirect: {res_dash_anon.headers.get('Location')})"
    )

    # --- Test 10: Clean up test records ---
    if user_row:
        execute_query("DELETE FROM scans WHERE user_id = %s", (user_row["id"],), commit=True)
        execute_query("DELETE FROM users WHERE id = %s", (user_row["id"],), commit=True)
    if guest_scan_id:
        execute_query("DELETE FROM scans WHERE id = %s", (guest_scan_id,), commit=True)

    print("\n" + "=" * 65)
    print(f" Summary: {passed}/{total} Tests PASSED")
    print("=" * 65)

    return passed == total


if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)
