"""
TrustGuard AI — Screenshot OCR Verification Suite
Tests image validation, file type restrictions, file size limits,
temporary file cleanup on success and error, scanner integration,
and error handling when Tesseract is missing or produces empty output.
"""

import sys
import io
import os
from pathlib import Path
from PIL import Image, ImageDraw

from app import app
import app as app_module
from config import Config, BASE_DIR
from ocr import (
    validate_image_file,
    extract_text_from_image,
    is_tesseract_available,
    resolve_tesseract_cmd,
)
from db import fetch_one, execute_query


def create_test_image(text="TEST SCAM ALERT", width=350, height=120, bg_color="white", text_color="black"):
    """Helper to create an in-memory PNG image with rendered text using Pillow."""
    img = Image.new("RGB", (width, height), color=bg_color)
    draw = ImageDraw.Draw(img)
    # Draw simple readable text
    draw.text((20, 45), text, fill=text_color)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return buf


def run_ocr_tests():
    print("=" * 65)
    print(" TrustGuard AI — Screenshot OCR Verification Suite")
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

    temp_test_dir = Config.UPLOAD_FOLDER
    os.makedirs(temp_test_dir, exist_ok=True)

    # -------------------------------------------------------------------------
    # Test 1: Image File Validation (Valid PNG Image)
    # -------------------------------------------------------------------------
    valid_img_path = temp_test_dir / "valid_test.png"
    try:
        with open(valid_img_path, "wb") as f:
            f.write(create_test_image("Hello World").getvalue())
        is_val, msg = validate_image_file(valid_img_path)
        assert_test("1. Validate Legitimate PNG Image", is_val is True, f"({msg})")
    finally:
        if valid_img_path.exists():
            valid_img_path.unlink()

    # -------------------------------------------------------------------------
    # Test 2: Reject Invalid File Extension (.txt / .exe)
    # -------------------------------------------------------------------------
    invalid_ext_path = temp_test_dir / "malicious.exe"
    try:
        with open(invalid_ext_path, "wb") as f:
            f.write(b"NOT_AN_IMAGE")
        is_val, msg = validate_image_file(invalid_ext_path)
        assert_test("2. Reject Invalid Extension (.exe)", is_val is False and "Unsupported" in msg, f"({msg})")
    finally:
        if invalid_ext_path.exists():
            invalid_ext_path.unlink()

    # -------------------------------------------------------------------------
    # Test 3: Reject Corrupted / Fake Image
    # -------------------------------------------------------------------------
    corrupt_img_path = temp_test_dir / "fake_image.png"
    try:
        with open(corrupt_img_path, "wb") as f:
            f.write(b"RIFF\x00\x00\x00\x00WEBPTHIS_IS_CORRUPTED_GARBAGE_BYTES")
        is_val, msg = validate_image_file(corrupt_img_path)
        assert_test("3. Reject Corrupted Image Content", is_val is False and "corrupted" in msg, f"({msg})")
    finally:
        if corrupt_img_path.exists():
            corrupt_img_path.unlink()

    # -------------------------------------------------------------------------
    # Test 4: Reject Empty File (0 Bytes)
    # -------------------------------------------------------------------------
    empty_file_path = temp_test_dir / "empty.jpg"
    try:
        with open(empty_file_path, "wb") as f:
            pass
        is_val, msg = validate_image_file(empty_file_path)
        assert_test("4. Reject Empty (0-byte) File", is_val is False and "empty" in msg, f"({msg})")
    finally:
        if empty_file_path.exists():
            empty_file_path.unlink()

    # -------------------------------------------------------------------------
    # Test 5: Temporary Uploads Deletion Policy on API Errors
    # -------------------------------------------------------------------------
    initial_uploads_count = len(list(temp_test_dir.glob("*.*")))

    # Send an invalid file type to /api/scan
    bad_data = {
        "screenshot": (io.BytesIO(b"malicious content"), "payload.sh"),
        "scan_type": "screenshot"
    }
    res_err = client.post("/api/scan", data=bad_data, content_type="multipart/form-data")
    after_err_count = len(list(temp_test_dir.glob("*.*")))

    assert_test(
        "5. Temp File Cleanup on Invalid Upload",
        res_err.status_code == 400 and after_err_count == initial_uploads_count,
        f"(Uploads remaining: {after_err_count - initial_uploads_count})"
    )

    # -------------------------------------------------------------------------
    # Test 6: Missing Screenshot Payload Validation
    # -------------------------------------------------------------------------
    res_no_file = client.post(
        "/api/scan",
        data={"scan_type": "screenshot"},
        content_type="multipart/form-data"
    )
    assert_test(
        "6. Missing Screenshot Payload Validation",
        res_no_file.status_code == 400 and "No screenshot file" in res_no_file.get_json().get("error", ""),
        f"(Status: {res_no_file.status_code})"
    )

    # -------------------------------------------------------------------------
    # Test 7: OCR Status API Endpoint
    # -------------------------------------------------------------------------
    res_status = client.get("/api/ocr/status")
    status_json = res_status.get_json() or {}
    assert_test(
        "7. GET /api/ocr/status Diagnostic",
        res_status.status_code == 200 and "available" in status_json,
        f"(Available: {status_json.get('available')})"
    )

    # -------------------------------------------------------------------------
    # Test 8: End-to-End Pipeline with Mocked / Actual OCR
    # -------------------------------------------------------------------------
    # We test that when OCR text is extracted, it routes directly into scanner.analyze_content()
    # and saves properly with scan_type = 'screenshot'
    import ocr
    original_extract = ocr.extract_text_from_image

    try:
        # Mock successful OCR text extraction to test the complete server pipeline
        # regardless of whether the external tesseract binary is currently on the machine
        mock_scam_text = (
            "URGENT NOTICE: Your PayPal account has been suspended due to suspicious activity. "
            "Please confirm your credentials and transfer $200 via Bitcoin immediately."
        )

        def mock_extract(path):
            return {
                "success": True,
                "text": mock_scam_text,
                "error": None,
                "char_count": len(mock_scam_text)
            }

        ocr.extract_text_from_image = mock_extract
        app_module.extract_text_from_image = mock_extract

        test_img_bytes = create_test_image("URGENT NOTICE: PayPal Account Suspended").getvalue()
        upload_data = {
            "screenshot": (io.BytesIO(test_img_bytes), "screenshot_evidence.png"),
            "scan_type": "screenshot"
        }

        # 8a: Guest Screenshot Scan
        res_guest_scan = client.post("/api/scan", data=upload_data, content_type="multipart/form-data")
        guest_json = res_guest_scan.get_json() or {}

        guest_scan_passed = (
            res_guest_scan.status_code == 200 and
            guest_json.get("success") is True and
            guest_json.get("data", {}).get("scan_type") == "screenshot" and
            guest_json.get("data", {}).get("extracted_text") == mock_scam_text and
            guest_json.get("data", {}).get("risk_score") >= 70 and
            guest_json.get("data", {}).get("is_authenticated") is False
        )

        assert_test(
            "8. Screenshot Scan Pipeline (Guest)",
            guest_scan_passed,
            f"(Score: {guest_json.get('data', {}).get('risk_score')}, Type: {guest_json.get('data', {}).get('scan_type')})"
        )

        guest_scan_id = guest_json.get("data", {}).get("scan_id")
        if guest_scan_id:
            db_row = fetch_one("SELECT user_id, scan_type, risk_level FROM scans WHERE id = %s", (guest_scan_id,))
            assert_test(
                "9. Database Scan Type & Guest Isolation",
                db_row is not None and db_row["user_id"] is None and db_row["scan_type"] == "screenshot",
                f"(DB scan_type: {db_row['scan_type'] if db_row else 'None'}, user_id: {db_row['user_id'] if db_row else 'None'})"
            )
            execute_query("DELETE FROM scans WHERE id = %s", (guest_scan_id,), commit=True)

        # ---------------------------------------------------------------------
        # Test 10: Temporary File Deletion Verification after Successful Scan
        # ---------------------------------------------------------------------
        after_success_count = len(list(temp_test_dir.glob("ocr_*.*")))
        assert_test(
            "10. Temp File Cleanup on Successful Scan",
            after_success_count == 0,
            f"(Orphan temporary files in uploads: {after_success_count})"
        )

        # ---------------------------------------------------------------------
        # Test 11: Empty OCR Result Error Handling
        # -------------------------------------------------------------------------
        def mock_empty_extract(path):
            return {
                "success": False,
                "text": "",
                "error": "No readable text could be detected in this screenshot.",
                "char_count": 0
            }

        ocr.extract_text_from_image = mock_empty_extract
        app_module.extract_text_from_image = mock_empty_extract

        res_empty_ocr = client.post(
            "/api/scan",
            data={"screenshot": (io.BytesIO(test_img_bytes), "blank.png"), "scan_type": "screenshot"},
            content_type="multipart/form-data"
        )
        assert_test(
            "11. Empty OCR Output User-Friendly Error",
            res_empty_ocr.status_code == 400 and "No readable text" in res_empty_ocr.get_json().get("error", ""),
            f"(Message: {res_empty_ocr.get_json().get('error')})"
        )

        # ---------------------------------------------------------------------
        # Test 12: Missing Tesseract Engine Error Handling
        # -------------------------------------------------------------------------
        def mock_missing_tess(path):
            return {
                "success": False,
                "text": "",
                "error": "Tesseract OCR executable is not installed or could not be found.",
                "char_count": 0
            }

        ocr.extract_text_from_image = mock_missing_tess
        app_module.extract_text_from_image = mock_missing_tess

        res_missing = client.post(
            "/api/scan",
            data={"screenshot": (io.BytesIO(test_img_bytes), "sample.png"), "scan_type": "screenshot"},
            content_type="multipart/form-data"
        )
        assert_test(
            "12. Missing Tesseract Engine Error Handling",
            res_missing.status_code == 400 and "Tesseract OCR" in res_missing.get_json().get("error", ""),
            f"(Status: {res_missing.status_code})"
        )

    finally:
        # Restore real function pointer
        ocr.extract_text_from_image = original_extract
        app_module.extract_text_from_image = original_extract

    # -------------------------------------------------------------------------
    # Test 13: Live End-to-End Tesseract OCR Scan (Real Image & Binary Execution)
    # -------------------------------------------------------------------------
    has_tess, tess_info = is_tesseract_available()
    if has_tess:
        real_phishing_text = "URGENT: Your PayPal account has been suspended! Call 1-800-555-0199"
        real_img_bytes = create_test_image(real_phishing_text, width=650, height=140).getvalue()
        real_upload = {
            "screenshot": (io.BytesIO(real_img_bytes), "live_test_phishing.png"),
            "scan_type": "screenshot"
        }
        res_live = client.post("/api/scan", data=real_upload, content_type="multipart/form-data")
        live_json = res_live.get_json() or {}
        live_data = live_json.get("data", {})
        live_extracted = live_data.get("extracted_text", "")

        live_passed = (
            res_live.status_code == 200 and
            live_json.get("success") is True and
            live_data.get("scan_type") == "screenshot" and
            ("PayPal" in live_extracted or "suspended" in live_extracted) and
            live_data.get("risk_score", 0) >= 50 and
            len(live_data.get("detected_flags", [])) > 0 and
            len(live_data.get("recommendations", [])) > 0 and
            "disclaimer" in live_data
        )

        assert_test(
            "13. Live End-to-End Tesseract OCR Scan",
            live_passed,
            f"(Score: {live_data.get('risk_score')}, Flags: {len(live_data.get('detected_flags', []))}, Extracted: '{live_extracted}')"
        )

        # Cleanup DB record created by live scan test
        live_scan_id = live_data.get("scan_id")
        if live_scan_id:
            execute_query("DELETE FROM scans WHERE id = %s", (live_scan_id,), commit=True)

        # Confirm no orphan temporary files
        live_temp_remaining = len(list(temp_test_dir.glob("ocr_*.*")))
        assert_test(
            "14. Temp File Cleanup on Real OCR Scan",
            live_temp_remaining == 0,
            f"(Uploads remaining: {live_temp_remaining})"
        )
    else:
        assert_test("13. Live End-to-End Tesseract OCR Scan", False, "(Tesseract binary unavailable)")

    # -------------------------------------------------------------------------
    # Live Tesseract Detection Summary
    # -------------------------------------------------------------------------
    print("\n" + "-" * 65)
    print(" Live Tesseract Binary Detection Check:")
    if has_tess:
        print(f" [+] Tesseract binary is installed and active at: {tess_info}")
    else:
        print(f" [!] Tesseract binary is currently not installed: {tess_info}")
    print("-" * 65)

    print("\n" + "=" * 65)
    print(f" Summary: {passed}/{total} OCR Verification Tests PASSED")
    print("=" * 65)

    return passed == total


if __name__ == "__main__":
    success = run_ocr_tests()
    sys.exit(0 if success else 1)
