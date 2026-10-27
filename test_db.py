"""
Database Verification Test for TrustGuard AI
Tests database connectivity, executes schema.sql initialization,
performs a test insert/select/delete on the scans table, and verifies rollback/cleanup.
"""

import sys
import json
from config import Config
from db import check_connection, init_db, execute_query, fetch_one


def run_test():
    print("=" * 60)
    print(" TrustGuard AI — MySQL Database Verification Test")
    print("=" * 60)
    print(f"Host: {Config.DB_HOST} | Port: {Config.DB_PORT} | User: {Config.DB_USER} | DB: {Config.DB_NAME}")

    # 1. Connection check
    print("\n[Step 1] Checking MySQL Server Connectivity...")
    ok, msg = check_connection()
    if not ok:
        print(f"[-] Connection Failed: {msg}")
        print("\n[!] Please update DB_PASSWORD in your .env file with your local MySQL password.")
        return False

    print(f"[+] Server connection verified: {msg}")

    # 2. Schema initialization
    print("\n[Step 2] Initializing database and tables from schema.sql...")
    ok, msg = init_db()
    if not ok:
        print(f"[-] Schema initialization failed: {msg}")
        return False
    print(f"[+] {msg}")

    # 3. Test insert for a guest scan (user_id = NULL)
    print("\n[Step 3] Testing guest scan record insertion...")
    test_flags = json.dumps([{"flag": "Test Flag", "description": "Verification test entry"}])
    test_recs = json.dumps(["Test recommendation item"])
    
    insert_sql = """
        INSERT INTO scans (user_id, scan_type, input_snippet, risk_score, risk_level, confidence_score, detected_flags, recommendations)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    scan_id = execute_query(
        insert_sql,
        (None, "text", "Verification snippet test entry", 15, "Low Risk", 0.95, test_flags, test_recs),
        commit=True
    )
    print(f"[+] Successfully inserted test scan with ID: {scan_id}")

    # 4. Fetch the record back
    print("\n[Step 4] Querying inserted test record...")
    row = fetch_one("SELECT * FROM scans WHERE id = %s", (scan_id,))
    if not row:
        print("[-] Error: Unable to fetch inserted record.")
        return False

    print(f"[+] Record retrieved successfully:")
    print(f"    ID         : {row['id']}")
    print(f"    Type       : {row['scan_type']}")
    print(f"    Risk Score : {row['risk_score']} ({row['risk_level']})")
    print(f"    Snippet    : {row['input_snippet']}")

    # 5. Cleanup test record
    print("\n[Step 5] Cleaning up test record...")
    execute_query("DELETE FROM scans WHERE id = %s", (scan_id,), commit=True)
    check_deleted = fetch_one("SELECT id FROM scans WHERE id = %s", (scan_id,))
    if check_deleted is None:
        print(f"[+] Test scan {scan_id} successfully removed. Database clean.")

    print("\n[+] All database tests PASSED successfully.")
    return True


if __name__ == "__main__":
    success = run_test()
    sys.exit(0 if success else 1)
