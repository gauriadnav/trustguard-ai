import logging
import os
from pathlib import Path
from config import Config

logger = logging.getLogger(__name__)

# Prefer mysql.connector, fall back to pymysql if needed
try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
    USE_CONNECTOR = True
except ImportError:
    import pymysql
    from pymysql import Error as MySQLError
    USE_CONNECTOR = False


def get_db_connection(select_db=True):
    """
    Establish and return a MySQL connection using configured credentials.
    If select_db is False, connects to the server without selecting a specific database.

    SSL/TLS behaviour
    -----------------
    - Remote hosts (anything that is not localhost / 127.0.0.1 / ::1) always
      connect over SSL so that traffic to Aiven MySQL is encrypted.
    - Set the environment variable DB_SSL_CA to the absolute path of the CA
      certificate file downloaded from the Aiven console (ca.pem).  When the
      file exists, full certificate and hostname verification is enabled.
    - If DB_SSL_CA is absent or the file cannot be found, SSL is still enabled
      but certificate verification is skipped.  A WARNING is always logged in
      this case so the degraded mode is never silent in production.
    - Local connections (localhost / 127.0.0.1 / ::1) are left unchanged and
      do not use SSL, preserving existing local-development behaviour.
    """
    conn_params = {
        "host":     Config.DB_HOST,
        "port":     Config.DB_PORT,
        "user":     Config.DB_USER,
        "password": Config.DB_PASSWORD,
    }
    if select_db:
        conn_params["database"] = Config.DB_NAME

    # ── SSL configuration ────────────────────────────────────────────────────
    _local_hosts = {"localhost", "127.0.0.1", "::1"}
    is_remote = Config.DB_HOST.lower() not in _local_hosts
    ssl_ca = os.getenv("DB_SSL_CA", "").strip()

    if USE_CONNECTOR:
        if is_remote:
            if ssl_ca and Path(ssl_ca).exists():
                # Full certificate + hostname verification using the Aiven CA cert.
                conn_params["ssl_ca"] = ssl_ca
                conn_params["ssl_verify_cert"] = True
                conn_params["ssl_verify_identity"] = True
                logger.debug("SSL enabled with CA verification: %s", ssl_ca)
            else:
                # No valid CA certificate: refuse to connect rather than
                # silently degrading to unverified TLS.  Fail clearly so
                # the misconfiguration is immediately visible.
                if not ssl_ca:
                    raise RuntimeError(
                        "DB_SSL_CA is required for remote MySQL connections but is "
                        "not set.  Download ca.pem from the Aiven console and set "
                        "DB_SSL_CA to its absolute path."
                    )
                raise RuntimeError(
                    f"DB_SSL_CA is set to '{ssl_ca}' but that file does not exist.  "
                    "Verify the path and ensure the CA certificate is present on "
                    "this server."
                )
        return mysql.connector.connect(**conn_params)
    else:
        conn_params_pymysql = dict(conn_params)
        if "database" in conn_params_pymysql:
            conn_params_pymysql["db"] = conn_params_pymysql.pop("database")
        conn_params_pymysql["cursorclass"] = pymysql.cursors.DictCursor
        conn_params_pymysql["autocommit"] = False
        if is_remote:
            if ssl_ca and Path(ssl_ca).exists():
                conn_params_pymysql["ssl"] = {"ca": ssl_ca}
                logger.debug("SSL enabled with CA verification: %s", ssl_ca)
            else:
                if not ssl_ca:
                    raise RuntimeError(
                        "DB_SSL_CA is required for remote MySQL connections but is "
                        "not set.  Download ca.pem from the Aiven console and set "
                        "DB_SSL_CA to its absolute path."
                    )
                raise RuntimeError(
                    f"DB_SSL_CA is set to '{ssl_ca}' but that file does not exist.  "
                    "Verify the path and ensure the CA certificate is present on "
                    "this server."
                )
        return pymysql.connect(**conn_params_pymysql)


def check_connection():
    """
    Verify database connectivity.
    Returns (success: bool, message: str).
    """
    try:
        conn = get_db_connection(select_db=False)
        conn.close()
        return True, "Database server connection successful."
    except Exception as e:
        return False, str(e)


def init_db(schema_path=None):
    """
    Initialize the database by executing the DDL statements in schema.sql.

    Cloud / Aiven compatibility
    ---------------------------
    Aiven MySQL provides a pre-created database; the application user does not
    have CREATE DATABASE or global USE privileges.  This function handles both
    cases transparently:

    1. If the configured database can be reached directly (cloud or an existing
       local database), it connects to it immediately and skips any
       ``CREATE DATABASE`` and ``USE`` statements in the schema file.
    2. If the direct connection fails (e.g. a fresh local MySQL installation
       where the database has not yet been created), it falls back to a
       server-level connection and executes the full schema including
       ``CREATE DATABASE`` and ``USE``.
    """
    if schema_path is None:
        from config import BASE_DIR
        schema_path = BASE_DIR / "schema.sql"

    with open(schema_path, "r", encoding="utf-8") as f:
        sql_content = f.read()

    # Split by semicolon; discard empty fragments.
    statements = [stmt.strip() for stmt in sql_content.split(";") if stmt.strip()]

    # ── Connection strategy ──────────────────────────────────────────────────
    # Attempt to connect to the target database directly first (works for
    # Aiven and any existing local database).  If that fails, the database
    # probably does not exist yet; fall back to a server-level connection so
    # that the CREATE DATABASE / USE statements in the schema can run.
    # MySQL error 1049 = ER_BAD_DB_ERROR ("Unknown database 'x'").
    # This is the only error that justifies falling back to a server-level
    # connection (fresh local MySQL where the database has not yet been
    # created).  Every other error — wrong credentials, network failure,
    # SSL misconfiguration, access denied — is re-raised immediately.
    _ER_BAD_DB_ERROR = 1049

    skip_db_ddl = False
    try:
        conn = get_db_connection(select_db=True)
        skip_db_ddl = True
        logger.debug(
            "Connected directly to database '%s'; CREATE DATABASE and USE "
            "statements will be skipped.",
            Config.DB_NAME,
        )
    except Exception as exc:
        # Extract the MySQL error number from both drivers.
        # mysql.connector.Error exposes .errno directly.
        # pymysql.Error stores the code in .args[0].
        errno = getattr(exc, "errno", None)
        if errno is None and exc.args:
            try:
                errno = int(exc.args[0])
            except (TypeError, ValueError):
                errno = None
        if errno != _ER_BAD_DB_ERROR:
            # Not "unknown database" — re-raise so the real cause
            # (wrong password, SSL error, network timeout, etc.) is
            # visible rather than hidden by the fallback path.
            raise
        logger.debug(
            "Database '%s' does not exist yet (MySQL 1049); falling back to "
            "server-level connection for local first-time initialization.",
            Config.DB_NAME,
        )
        conn = get_db_connection(select_db=False)

    cursor = conn.cursor()
    try:
        executed = 0
        skipped = 0
        for stmt in statements:
            upper_stmt = stmt.upper().lstrip()
            # Skip CREATE DATABASE and USE when the DB already exists or when
            # the user lacks the required server-level privileges (Aiven).
            if skip_db_ddl and (
                upper_stmt.startswith("CREATE DATABASE")
                or upper_stmt.startswith("USE ")
            ):
                skipped += 1
                logger.debug("Skipped DDL statement: %.60s", stmt)
                continue
            cursor.execute(stmt)
            executed += 1
        conn.commit()
        # Apply incremental migrations (is_admin column, community_reports table, seed data).
        migrate_ok, migrate_msg = migrate_schema()
        skip_note = f", skipped {skipped} DDL statement(s)" if skipped else ""
        return True, (
            f"Executed {executed} statement(s) from {schema_path.name}"
            f"{skip_note}. ({migrate_msg})"
        )
    except Exception as e:
        conn.rollback()
        return False, f"Failed to initialize database: {e}"
    finally:
        cursor.close()
        conn.close()


def migrate_schema():
    """
    Apply incremental migrations safely without modifying or deleting existing records:
    1. Ensure 'is_admin' column exists on 'users' table.
    2. Ensure 'community_reports' table exists.
    3. Seed initial educational approved community reports if table is empty.
    """
    try:
        conn = get_db_connection(select_db=True)
        cursor = conn.cursor()

        # 1. Check and add is_admin column if missing
        cursor.execute(
            """
            SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = %s AND TABLE_NAME = 'users' AND COLUMN_NAME = 'is_admin'
            """,
            (Config.DB_NAME,)
        )
        row = cursor.fetchone()
        col_count = row[0] if (row and not isinstance(row, dict)) else (row.get('COUNT(*)', 0) if isinstance(row, dict) else 0)
        if col_count == 0:
            cursor.execute("ALTER TABLE users ADD COLUMN is_admin TINYINT(1) NOT NULL DEFAULT 0")
            conn.commit()

        # 2. Check and create community_reports table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS community_reports (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NULL,
                category VARCHAR(50) NOT NULL,
                scam_type VARCHAR(30) NOT NULL DEFAULT 'text',
                evidence_snippet TEXT NOT NULL,
                description TEXT NOT NULL,
                indicators TEXT NULL,
                status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                CONSTRAINT fk_reports_user
                    FOREIGN KEY (user_id) REFERENCES users(id)
                    ON DELETE SET NULL,
                INDEX idx_reports_status (status),
                INDEX idx_reports_category (category),
                INDEX idx_reports_created (created_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
        """)
        conn.commit()

        # 3. Seed educational sample approved reports if table is empty
        cursor.execute("SELECT COUNT(*) FROM community_reports")
        r_row = cursor.fetchone()
        r_count = r_row[0] if (r_row and not isinstance(r_row, dict)) else (r_row.get('COUNT(*)', 0) if isinstance(r_row, dict) else 0)

        if r_count == 0:
            import json
            seed_sql = """
                INSERT INTO community_reports (user_id, category, scam_type, evidence_snippet, description, indicators, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """
            samples = [
                (
                    None,
                    "Phishing / SMS",
                    "text",
                    "URGENT: Your Netflix membership is on hold due to a billing issue. Update payment within 24 hours at http://netflix-secure-billing.xyz to avoid cancellation.",
                    "Received an unexpected text claiming my Netflix account was suspended. The URL pointed to a suspicious .xyz domain rather than netflix.com, and used pressure tactics.",
                    json.dumps(["Suspicious .xyz TLD", "High Urgency / Coercive Deadline", "Payment Detail Request"]),
                    "approved"
                ),
                (
                    None,
                    "Fake Job Offer",
                    "job_offer",
                    "Congratulations! Selected for Remote Data Entry Specialist. Earn $850/day. Equipment shipping requires $120 refundable clearance fee via Bitcoin or Steam gift card.",
                    "Recruiter approached via WhatsApp offering an unrealistic salary without any interview. Demanded an upfront equipment clearance fee via untraceable payment channels.",
                    json.dumps(["Unrealistic Daily Compensation", "Upfront Fee Requirement", "Untraceable Cryptocurrency Payment"]),
                    "approved"
                )
            ]
            for s in samples:
                cursor.execute(seed_sql, s)
            conn.commit()

        cursor.close()
        conn.close()
        return True, "Schema migrations applied successfully."
    except Exception as e:
        logger.error(f"Migration error: {e}")
        return False, str(e)



def execute_query(query, params=None, commit=True):
    """
    Execute a parameterized SQL query (INSERT, UPDATE, DELETE).
    Returns lastrowid for INSERTs, or rowcount.
    """
    conn = get_db_connection(select_db=True)
    cursor = conn.cursor()
    try:
        cursor.execute(query, params or ())
        if commit:
            conn.commit()
        last_id = cursor.lastrowid
        row_count = cursor.rowcount
        return last_id if last_id else row_count
    except Exception as e:
        conn.rollback()
        logger.error(f"Query execution error: {e}")
        raise e
    finally:
        cursor.close()
        conn.close()


def fetch_one(query, params=None):
    """
    Execute a parameterized SELECT query and return one record as a dictionary.
    """
    conn = get_db_connection(select_db=True)
    cursor = conn.cursor(dictionary=True) if USE_CONNECTOR else conn.cursor()
    try:
        cursor.execute(query, params or ())
        result = cursor.fetchone()
        return result
    finally:
        cursor.close()
        conn.close()


def fetch_all(query, params=None):
    """
    Execute a parameterized SELECT query and return all matching records as dictionaries.
    """
    conn = get_db_connection(select_db=True)
    cursor = conn.cursor(dictionary=True) if USE_CONNECTOR else conn.cursor()
    try:
        cursor.execute(query, params or ())
        results = cursor.fetchall()
        return results
    finally:
        cursor.close()
        conn.close()
