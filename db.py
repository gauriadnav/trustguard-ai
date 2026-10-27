import logging
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
    """
    conn_params = {
        "host": Config.DB_HOST,
        "port": Config.DB_PORT,
        "user": Config.DB_USER,
        "password": Config.DB_PASSWORD,
    }
    if select_db:
        conn_params["database"] = Config.DB_NAME

    if USE_CONNECTOR:
        return mysql.connector.connect(**conn_params)
    else:
        conn_params_pymysql = dict(conn_params)
        if "database" in conn_params_pymysql:
            conn_params_pymysql["db"] = conn_params_pymysql.pop("database")
        conn_params_pymysql["cursorclass"] = pymysql.cursors.DictCursor
        conn_params_pymysql["autocommit"] = False
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
    Initialize the database using schema.sql.
    Executes table creation commands safely.
    """
    if schema_path is None:
        from config import BASE_DIR
        schema_path = BASE_DIR / "schema.sql"

    with open(schema_path, "r", encoding="utf-8") as f:
        sql_content = f.read()

    # Connect to MySQL server (without selecting DB, as schema creates it)
    conn = get_db_connection(select_db=False)
    cursor = conn.cursor()

    try:
        # Split by semicolon to run statements sequentially
        statements = [stmt.strip() for stmt in sql_content.split(";") if stmt.strip()]
        for stmt in statements:
            cursor.execute(stmt)
        conn.commit()
        # Apply incremental migrations (e.g. community_reports table and is_admin column)
        migrate_ok, migrate_msg = migrate_schema()
        return True, f"Successfully executed {len(statements)} statements from {schema_path.name}. ({migrate_msg})"
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
