"""
TrustGuard AI — Community Scam Reporting & Multilingual Verification Suite
Tests:
1. Community Reports listing & public filtering of pending submissions.
2. Report submission validation (length, category, neutral anti-defamation check).
3. Guest report submission (user_id IS NULL) and separation from authenticated users.
4. Pending report public invisibility (WHERE status = 'approved').
5. Submission anti-spam cooldown and 24h exact duplicate rejection.
6. Authorization guards on /community/moderate and POST /api/community/reports/<id>/status:
   - Unauthenticated requests rejected (401 / redirect).
   - Non-admin authenticated users rejected (403 / redirect).
   - Authorized admin approval updates status to 'approved'.
   - Newly approved report becomes visible on /community.
7. Language detection across English, Spanish, French, German, and Unsupported.
8. Tier 1 English analysis uses TF-IDF ML model (ml_applied == True).
9. Tier 2 Spanish, French, German use localized heuristics & URL forensics with ML bypassed (ml_applied == False).
10. Tier 3 Unsupported languages handle honesty note and universal URL forensics.
11. Local URL forensics detect threats regardless of surrounding language.
12. Screenshot OCR handles language parameter and falls back gracefully when specific Tesseract language pack is missing.
"""

import sys
import io
import json
import time
from pathlib import Path
from PIL import Image, ImageDraw

from app import app
from config import Config
from db import fetch_one, fetch_all, execute_query
from scanner import detect_language, analyze_content
from ocr import extract_text_from_image, get_installed_ocr_languages


def create_test_image(text="ALERTA URGENTE: Cuenta suspendida", width=380, height=120):
    """Helper to generate an in-memory test image."""
    img = Image.new("RGB", (width, height), color="white")
    draw = ImageDraw.Draw(img)
    draw.text((20, 45), text, fill="black")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def run_tests():
    print("=" * 70)
    print(" TrustGuard AI — Community Reporting & Multilingual Verification Suite")
    print("=" * 70)

    client = app.test_client()
    passed = 0
    total = 0
    created_report_ids = []
    created_user_ids = []

    def assert_test(name, condition, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"[PASS] {total}. {name} {details}")
            return True
        else:
            print(f"[FAIL] {total}. {name} {details}")
            return False

    try:
        # =====================================================================
        # PART 1: COMMUNITY SCAM REPORTING TESTS
        # =====================================================================
        print("\n--- Section 1: Community Scam Reporting & Visibility ---")

        # Test 1: Public community feed returns HTTP 200
        res = client.get("/community")
        assert_test("GET /community Public Feed", res.status_code == 200, f"(Status: {res.status_code})")

        # Test 2: Input validation - missing category
        res = client.post("/api/community/reports", json={
            "category": "",
            "evidence_snippet": "Urgent fake bank alert http://bad-link.xyz",
            "description": "This message asked me to wire money immediately."
        })
        assert_test("Reject Empty Category", res.status_code == 400, f"(Status: {res.status_code})")

        # Test 3: Input validation - evidence too short
        res = client.post("/api/community/reports", json={
            "category": "Phishing / SMS",
            "evidence_snippet": "bad",
            "description": "This message asked me to wire money immediately."
        })
        assert_test("Reject Too Short Evidence Snippet", res.status_code == 400, f"(Status: {res.status_code})")

        # Test 4: Input validation - description too short
        res = client.post("/api/community/reports", json={
            "category": "Phishing / SMS",
            "evidence_snippet": "URGENT: Your account is suspended at http://fake.xyz",
            "description": "Too short"
        })
        assert_test("Reject Too Short Description", res.status_code == 400, f"(Status: {res.status_code})")

        # Test 5: Neutral phrasing guard - reject personal accusation/defamation
        res = client.post("/api/community/reports", json={
            "category": "Other",
            "evidence_snippet": "Payment request from user John",
            "description": "he is a thief and stole all my money hate him"
        })
        assert_test("Reject Defamatory Personal Accusation", res.status_code == 400, f"(Status: {res.status_code})")

        # Test 6: Valid guest report submission creates pending record
        unique_snippet = f"URGENT VERIFICATION ALERT #{int(time.time())}: Update bank account at http://secure-verify-{int(time.time())}.xyz"
        res = client.post("/api/community/reports", json={
            "category": "Phishing / SMS",
            "scam_type": "text",
            "evidence_snippet": unique_snippet,
            "description": "Received an unprompted SMS demanding immediate banking credential verification."
        })
        data = res.get_json() or {}
        report_id = data.get("report_id")
        if report_id:
            created_report_ids.append(report_id)

        assert_test(
            "Guest Report Submission Status",
            res.status_code == 201 and data.get("status") == "pending",
            f"(Report ID: {report_id}, Status: {data.get('status')})"
        )

        # Test 7: Database verification of guest report (user_id IS NULL)
        db_rep = fetch_one("SELECT id, user_id, status, evidence_snippet FROM community_reports WHERE id = %s", (report_id,))
        assert_test(
            "Guest Isolation in DB (user_id IS NULL)",
            db_rep is not None and db_rep.get("user_id") is None and db_rep.get("status") == "pending",
            f"(DB user_id: {db_rep.get('user_id') if db_rep else None}, Status: {db_rep.get('status') if db_rep else None})"
        )

        # Test 8: Pending report is HIDDEN from public /community feed
        res = client.get("/community")
        page_html = res.get_data(as_text=True)
        assert_test(
            "Pending Report Hidden from Public View",
            unique_snippet not in page_html,
            "(Confirmed pending snippet not present in public feed)"
        )

        # Test 9: Rapid re-submission triggers rate-limiting (429)
        res_rapid = client.post("/api/community/reports", json={
            "category": "Deceptive URL",
            "evidence_snippet": f"Another suspicious message #{int(time.time())}",
            "description": "Valid description explaining why this is suspicious."
        })
        assert_test(
            "Rapid Resubmission Cooldown (429)",
            res_rapid.status_code == 429,
            f"(Status: {res_rapid.status_code})"
        )

        # Test 10: Exact 24-hour duplicate evidence check (409)
        with client.session_transaction() as sess:
            sess["last_report_submit"] = 0  # Bypass cooldown timer to test duplicate check
        res_dup = client.post("/api/community/reports", json={
            "category": "Phishing / SMS",
            "evidence_snippet": unique_snippet,
            "description": "Attempting to submit identical evidence again."
        })
        assert_test(
            "Duplicate Evidence 24h Rejection (409)",
            res_dup.status_code == 409,
            f"(Status: {res_dup.status_code})"
        )

        # Test 11: Authenticated report submission links user_id properly
        test_uname = f"rep_user_{int(time.time()) % 100000}"
        test_email = f"{test_uname}@testguard.internal"
        client.post("/register", data={
            "username": test_uname,
            "email": test_email,
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        u_row = fetch_one("SELECT id FROM users WHERE username = %s", (test_uname,))
        reg_user_id = u_row["id"] if u_row else None
        if reg_user_id:
            created_user_ids.append(reg_user_id)

        with client.session_transaction() as sess:
            sess["last_report_submit"] = 0

        auth_snippet = f"Fake job offer notice #{int(time.time())}: Earn $500/day at http://jobs-{int(time.time())}.top"
        res_auth = client.post("/api/community/reports", json={
            "category": "Fake Job Offer",
            "scam_type": "job_offer",
            "evidence_snippet": auth_snippet,
            "description": "Work from home job requiring upfront equipment registration fee."
        })
        auth_data = res_auth.get_json() or {}
        auth_report_id = auth_data.get("report_id")
        if auth_report_id:
            created_report_ids.append(auth_report_id)

        db_auth_rep = fetch_one("SELECT user_id, status FROM community_reports WHERE id = %s", (auth_report_id,))
        assert_test(
            "Authenticated Report User Attribution",
            db_auth_rep is not None and db_auth_rep.get("user_id") == reg_user_id,
            f"(Linked to User ID: {db_auth_rep.get('user_id') if db_auth_rep else None})"
        )

        # =====================================================================
        # PART 2: MODERATION WORKFLOW & AUTHORIZATION GUARDS
        # =====================================================================
        print("\n--- Section 2: Moderation Permissions & Workflow ---")

        # Test 12: Unauthenticated moderation status update rejected (401)
        unauth_client = app.test_client()
        res_unauth = unauth_client.post(f"/api/community/reports/{report_id}/status", json={"status": "approved"})
        assert_test(
            "Unauthenticated API Moderation Denied (401)",
            res_unauth.status_code == 401,
            f"(Status: {res_unauth.status_code})"
        )

        # Test 13: Unauthenticated /community/moderate page visit redirects (302)
        res_unauth_page = unauth_client.get("/community/moderate")
        assert_test(
            "Unauthenticated Moderation Page Redirect",
            res_unauth_page.status_code == 302 and "/login" in res_unauth_page.headers.get("Location", ""),
            f"(Redirected to: {res_unauth_page.headers.get('Location')})"
        )

        # Test 14: Non-admin authenticated user denied moderation API (403)
        res_non_admin = client.post(f"/api/community/reports/{report_id}/status", json={"status": "approved"})
        assert_test(
            "Non-Admin API Moderation Denied (403)",
            res_non_admin.status_code == 403,
            f"(Status: {res_non_admin.status_code})"
        )

        # Test 15: Non-admin authenticated user visiting /community/moderate redirects away
        res_non_admin_page = client.get("/community/moderate")
        assert_test(
            "Non-Admin Moderation Page Redirect",
            res_non_admin_page.status_code == 302 and "/community" in res_non_admin_page.headers.get("Location", ""),
            f"(Redirected to: {res_non_admin_page.headers.get('Location')})"
        )

        # Test 16: Admin Registration & Safe Post-Login Next Redirect
        admin_client = app.test_client()
        admin_uname = f"admin_test_{int(time.time()) % 100000}"
        admin_email = f"{admin_uname}@testguard.internal"
        admin_client.post("/register", data={
            "username": admin_uname,
            "email": admin_email,
            "password": "Password123!",
            "confirm_password": "Password123!"
        })
        admin_row = fetch_one("SELECT id FROM users WHERE username = %s", (admin_uname,))
        admin_user_id = admin_row["id"] if admin_row else None
        if admin_user_id:
            created_user_ids.append(admin_user_id)
            execute_query("UPDATE users SET is_admin = 1 WHERE id = %s", (admin_user_id,), commit=True)

        # Log out so we can test the exact login redirection with ?next=/community/moderate
        admin_client.get("/logout")

        # Test safe redirect back to /community/moderate via form post
        res_login_next = admin_client.post(
            "/login?next=/community/moderate",
            data={
                "identifier": admin_uname,
                "password": "Password123!",
                "next": "/community/moderate"
            },
            follow_redirects=False
        )
        assert_test(
            "Post-Login Safe Next Redirect (/community/moderate)",
            res_login_next.status_code == 302 and res_login_next.headers.get("Location") == "/community/moderate",
            f"(Redirected to: {res_login_next.headers.get('Location')})"
        )

        # Test malicious open redirect rejection
        evil_client = app.test_client()
        res_evil = evil_client.post(
            "/login?next=https://malicious-scam.com/steal",
            data={
                "identifier": admin_uname,
                "password": "Password123!",
                "next": "https://malicious-scam.com/steal"
            },
            follow_redirects=False
        )
        assert_test(
            "Reject Malicious External Open Redirect",
            res_evil.status_code == 302 and "/dashboard" in res_evil.headers.get("Location", ""),
            f"(Safely redirected to: {res_evil.headers.get('Location')})"
        )

        # Admin visits /community/moderate
        res_admin_page = admin_client.get("/community/moderate")
        assert_test(
            "Authorized Admin Moderation Page Access (200)",
            res_admin_page.status_code == 200,
            f"(Status: {res_admin_page.status_code})"
        )

        # Admin approves report
        res_approve = admin_client.post(f"/api/community/reports/{report_id}/status", json={"status": "approved"})
        approve_data = res_approve.get_json() or {}
        assert_test(
            "Admin Approve Report API (200)",
            res_approve.status_code == 200 and (approve_data.get("new_status") == "approved" or approve_data.get("status") == "approved"),
            f"(New status: {approve_data.get('status') or approve_data.get('new_status')})"
        )

        # Test 17: Newly approved report is now visible on public /community
        res_pub_after = admin_client.get("/community")
        pub_html = res_pub_after.get_data(as_text=True)
        assert_test(
            "Approved Report Visible on Public Feed",
            unique_snippet in pub_html,
            "(Snippet now rendered in public community feed)"
        )

        # =====================================================================
        # PART 3: MULTILINGUAL SUPPORT & SCANNER BEHAVIOR
        # =====================================================================
        print("\n--- Section 3: Multilingual Detection & Threat Analysis ---")

        # Test 18: Language Detection Accuracy
        es_text = "Estimado cliente, su cuenta bancaria ha sido suspendida. Ingrese su contraseña inmediatamente para desbloquear."
        fr_text = "Cher client, votre compte a été suspendu. Entrez votre mot de passe immédiatement pour débloquer."
        de_text = "DRINGEND: Ihr Konto wurde gesperrt! Passwort sofort eingeben innerhalb von 24 Stunden zur Freischaltung."
        en_text = "URGENT: Your bank account has been suspended. Enter your password immediately."
        unsupported_text = "Срочно подтвердите пароль для доступа к аккаунту."

        assert_test("Detect Spanish", detect_language(es_text) == "es", f"(Detected: {detect_language(es_text)})")
        assert_test("Detect French", detect_language(fr_text) == "fr", f"(Detected: {detect_language(fr_text)})")
        assert_test("Detect German", detect_language(de_text) == "de", f"(Detected: {detect_language(de_text)})")
        assert_test("Detect English", detect_language(en_text) == "en", f"(Detected: {detect_language(en_text)})")
        assert_test("Detect Unsupported Script", detect_language(unsupported_text) == "other", f"(Detected: {detect_language(unsupported_text)})")

        # Test 19: Tier 1 English Hybrid Analysis (TF-IDF ML model applied)
        en_analysis = analyze_content(en_text, scan_type="text", language="en")
        assert_test(
            "Tier 1 English Analysis (ML Applied)",
            en_analysis["language_info"]["code"] == "en" and
            en_analysis["ml_applied"] is True and
            en_analysis["risk_score"] > 60 and
            "Tier 1" in en_analysis["language_info"]["tier"],
            f"(Score: {en_analysis['risk_score']}, ML Prob: {en_analysis['ml_probability']})"
        )

        # Test 20: Tier 2 Spanish Analysis (Localized Heuristics, ML explicitly bypassed)
        es_analysis = analyze_content(es_text, scan_type="text", language="es")
        flags_es = [f["flag"] for f in es_analysis.get("detected_flags", [])]
        assert_test(
            "Tier 2 Spanish Analysis (ML Bypassed, Heuristics Detected)",
            es_analysis["language_info"]["code"] == "es" and
            es_analysis["ml_applied"] is False and
            es_analysis["risk_score"] >= 70 and
            any("Alta Urgencia" in f or "Solicitud de Credenciales" in f for f in flags_es),
            f"(Score: {es_analysis['risk_score']}, Flags: {len(flags_es)}, Mode: {es_analysis['language_info']['mode']})"
        )

        # Test 21: Tier 2 French Analysis (Localized Heuristics, ML bypassed)
        fr_analysis = analyze_content(fr_text, scan_type="text", language="fr")
        flags_fr = [f["flag"] for f in fr_analysis.get("detected_flags", [])]
        assert_test(
            "Tier 2 French Analysis (ML Bypassed, Heuristics Detected)",
            fr_analysis["language_info"]["code"] == "fr" and
            fr_analysis["ml_applied"] is False and
            fr_analysis["risk_score"] >= 70 and
            any("Urgence" in f or "Identifiants" in f for f in flags_fr),
            f"(Score: {fr_analysis['risk_score']}, Flags: {len(flags_fr)})"
        )

        # Test 22: Tier 2 German Analysis (Localized Heuristics, ML bypassed)
        de_analysis = analyze_content(de_text, scan_type="text", language="de")
        flags_de = [f["flag"] for f in de_analysis.get("detected_flags", [])]
        assert_test(
            "Tier 2 German Analysis (ML Bypassed, Heuristics Detected)",
            de_analysis["language_info"]["code"] == "de" and
            de_analysis["ml_applied"] is False and
            de_analysis["risk_score"] >= 70 and
            any("Dringlichkeit" in f or "Zugangsdaten" in f for f in flags_de),
            f"(Score: {de_analysis['risk_score']}, Flags: {len(flags_de)})"
        )

        # Test 23: Tier 3 Unsupported Language Honest Handling
        other_text = "Тестовое сообщение без ссылок и известных паттернов."
        other_analysis = analyze_content(other_text, scan_type="text", language="other")
        assert_test(
            "Tier 3 Unsupported Language Advisory Note",
            other_analysis["language_info"]["code"] == "other" and
            other_analysis["ml_applied"] is False and
            "Tier 3" in other_analysis["language_info"]["tier"] and
            "not calibrated" in other_analysis["language_info"]["note"].lower(),
            f"(Tier: {other_analysis['language_info']['tier']})"
        )

        # Test 24: Universal URL Forensics in Multilingual Content
        multilingual_with_url = "Consulte su saldo ahora en http://192.168.1.100/paypal-update.xyz"
        url_analysis = analyze_content(multilingual_with_url, scan_type="text", language="es")
        url_flags = [f["flag"] for f in url_analysis.get("detected_flags", [])]
        assert_test(
            "Universal URL Forensics Active in Multilingual Content",
            any("Bare IP" in f or "High-Risk Top-Level Domain" in f for f in url_flags) and
            url_analysis["risk_score"] >= 70,
            f"(Score: {url_analysis['risk_score']}, URL flags found: {len(url_flags)})"
        )

        # =====================================================================
        # PART 4: SCREENSHOT OCR LANGUAGE BEHAVIOR
        # =====================================================================
        print("\n--- Section 4: Screenshot OCR & Language Integration ---")

        # Test 25: Tesseract Installed Language Discovery
        installed_langs = get_installed_ocr_languages()
        assert_test(
            "Tesseract Language Model Inspection",
            isinstance(installed_langs, list) and len(installed_langs) > 0 and "eng" in installed_langs,
            f"(Available: {installed_langs})"
        )

        # Test 26: Graceful OCR Language Fallback when requested pack is missing
        # 'spa' is not installed in local tessdata; verify it falls back to 'eng' gracefully without exception
        test_img_buf = create_test_image("URGENT: Verify your account immediately")
        temp_img_path = Config.UPLOAD_FOLDER / "test_multilang_ocr.png"
        with open(temp_img_path, "wb") as f:
            f.write(test_img_buf.getvalue())

        try:
            ocr_res = extract_text_from_image(temp_img_path, lang="es")
            assert_test(
                "OCR Graceful Fallback for Missing Language Pack",
                ocr_res["success"] is True and ocr_res["ocr_lang"] == "eng",
                f"(Success: {ocr_res['success']}, Fallback OCR Lang: {ocr_res.get('ocr_lang')})"
            )
        finally:
            if temp_img_path.exists():
                temp_img_path.unlink()

        # Test 27: End-to-End Multilingual Screenshot Scan via /api/scan
        test_screenshot = create_test_image("URGENT: Verify credentials at http://paypal.com.account-alert.xyz")
        res_ocr_scan = client.post(
            "/api/scan",
            data={
                "scan_type": "screenshot",
                "language": "en",
                "screenshot": (test_screenshot, "screenshot_test.png")
            },
            content_type="multipart/form-data"
        )
        scan_data = res_ocr_scan.get_json() or {}
        analysis_data = scan_data.get("data", {})
        assert_test(
            "End-to-End Multilingual Screenshot Scan API",
            res_ocr_scan.status_code == 200 and
            analysis_data.get("scan_type") == "screenshot" and
            "language_info" in analysis_data,
            f"(Status: {res_ocr_scan.status_code}, Score: {analysis_data.get('risk_score')}, Lang: {analysis_data.get('language_info', {}).get('code')})"
        )

    finally:
        # Clean up temporary test records to preserve database hygiene
        print("\n--- Cleaning up temporary test records ---")
        for rid in created_report_ids:
            execute_query("DELETE FROM community_reports WHERE id = %s", (rid,), commit=True)
        for uid in created_user_ids:
            execute_query("DELETE FROM scans WHERE user_id = %s", (uid,), commit=True)
            execute_query("DELETE FROM users WHERE id = %s", (uid,), commit=True)
        print(f"[+] Cleaned up {len(created_report_ids)} test reports and {len(created_user_ids)} test users.")

    print("\n" + "=" * 70)
    print(f" Summary: {passed}/{total} Verification Tests PASSED")
    print("=" * 70)
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
