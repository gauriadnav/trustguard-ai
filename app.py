"""
TrustGuard AI — Flask Application
Provides routes for scam analysis, user authentication, personal scan history,
and visual analytics dashboard.
"""

import time
import json
import re
import uuid
import logging
import urllib.parse
from pathlib import Path
from functools import wraps
from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    url_for,
    session,
    flash,
    abort,
)
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from db import execute_query, fetch_one, fetch_all, check_connection, init_db
from scanner import analyze_content
from ocr import extract_text_from_image, is_tesseract_available

# Configure application logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("trustguard")

app = Flask(__name__)
app.config.from_object(Config)

# Enforce secure cookie defaults
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=not Config.DEBUG,  # True in production (HTTPS); False in local dev (HTTP)
)

# ── Database initialization ───────────────────────────────────────────────────
# Runs once per Gunicorn worker process at startup (module-level import).
# Every operation is idempotent: CREATE TABLE IF NOT EXISTS, ALTER TABLE only
# when the column is missing, INSERT only when the table is empty.
# No credentials or connection strings are written to logs.
with app.app_context():
    try:
        _init_ok, _init_msg = init_db()
        if _init_ok:
            logger.info("Database initialized: %s", _init_msg)
        else:
            logger.error(
                "Database initialization reported failure. "
                "Check DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, "
                "and DB_SSL_CA environment variables."
            )
    except Exception as _init_exc:
        # Log only the exception class — not the message, which may contain
        # connection details such as host or username.
        logger.error(
            "Database initialization raised %s at startup. "
            "Check DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME, "
            "and DB_SSL_CA environment variables.",
            type(_init_exc).__name__,
        )


# -----------------------------------------------------------------------------
# Authentication Helpers & Decorators
# -----------------------------------------------------------------------------
def login_required(f):
    """Decorator to require authenticated user session for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to access your dashboard and scan history.", "warning")
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Decorator to require administrator access for community moderation."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"success": False, "error": "Authentication required. Please log in as an administrator."}), 401
            flash("Administrative access requires signing in.", "warning")
            return redirect(url_for("login", next=request.path))
        user = fetch_one("SELECT id, username, is_admin FROM users WHERE id = %s", (user_id,))
        is_admin_user = bool(user and (user.get("is_admin") or user.get("username") == "admin"))
        if not is_admin_user:
            if request.path.startswith("/api/") or request.is_json:
                return jsonify({"success": False, "error": "Administrative privileges required to perform this action."}), 403
            flash("Administrative privileges are required to access moderation.", "danger")
            return redirect(url_for("community_reports_page"))
        return f(*args, **kwargs)
    return decorated_function


@app.context_processor
def inject_user():
    """Inject current_user object into all Jinja2 templates."""
    user_id = session.get("user_id")
    if user_id:
        try:
            user = fetch_one("SELECT id, username, email, is_admin FROM users WHERE id = %s", (user_id,))
            if user:
                user["is_admin"] = bool(user.get("is_admin") or user.get("username") == "admin")
            return {"current_user": user}
        except Exception as e:
            logger.error(f"Error loading current user: {e}")
            return {"current_user": None}
    return {"current_user": None}



# -----------------------------------------------------------------------------
# Main & Scanner Routes
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    """Homepage with unified scanner interface."""
    return render_template("index.html")


@app.route("/api/ocr/status", methods=["GET"])
def ocr_status():
    """Check Tesseract OCR availability and binary path."""
    available, msg_or_path = is_tesseract_available()
    return jsonify({
        "available": available,
        "path_or_message": msg_or_path
    }), 200


@app.route("/api/scan", methods=["POST"])
def scan_api():
    """
    Asynchronous Scan Endpoint.
    Accepts JSON, Form data, or Multipart Screenshot Uploads.
    Extracts text via OCR when an image is provided, evaluates threat score,
    and safely logs to MySQL with automatic temporary file cleanup.
    """
    temp_image_path = None
    extracted_text = ""

    try:
        # 1. Determine input format, scan modality, and language
        scan_type = request.form.get("scan_type") or "text"
        language = request.form.get("language") or "auto"

        if request.is_json:
            data = request.get_json() or {}
            content = data.get("content", "")
            scan_type = data.get("scan_type", "text")
            language = data.get("language", "auto")
        else:
            content = request.form.get("content", "")

        # 2. Handle Screenshot Upload Modality
        is_screenshot = (
            scan_type == "screenshot" or
            "screenshot" in request.files or
            "file" in request.files
        )

        if is_screenshot:
            scan_type = "screenshot"
            file = request.files.get("screenshot") or request.files.get("file")

            if not file or not file.filename:
                return jsonify({
                    "success": False,
                    "error": "No screenshot file was provided. Please choose a valid image to upload."
                }), 400

            # Validate file extension
            orig_ext = Path(file.filename).suffix.lower()
            allowed_exts = {".png", ".jpg", ".jpeg", ".webp"}
            if orig_ext not in allowed_exts:
                return jsonify({
                    "success": False,
                    "error": f"Unsupported file type '{orig_ext}'. Please upload a PNG, JPG, JPEG, or WEBP screenshot."
                }), 400

            # Generate unique temporary file in uploads/
            temp_filename = f"ocr_{uuid.uuid4().hex}{orig_ext}"
            temp_image_path = Config.UPLOAD_FOLDER / temp_filename

            try:
                # Save uploaded file temporarily for inspection and OCR
                file.save(temp_image_path)

                # Process image and extract readable text
                try:
                    ocr_result = extract_text_from_image(temp_image_path, lang=language)
                except TypeError:
                    ocr_result = extract_text_from_image(temp_image_path)

                if not ocr_result["success"]:
                    # Return user-friendly error (e.g. missing tesseract, empty text, unreadable image)
                    return jsonify({
                        "success": False,
                        "error": ocr_result["error"]
                    }), 400

                extracted_text = ocr_result["text"]
                content = extracted_text

            finally:
                # Enforce complete temporary file deletion, even on errors
                if temp_image_path and temp_image_path.exists():
                    try:
                        temp_image_path.unlink()
                        logger.debug(f"Deleted temporary upload: {temp_image_path.name}")
                    except Exception as clean_err:
                        logger.warning(f"Failed to delete temporary file {temp_image_path}: {clean_err}")

        # 3. Validate text content
        content = (content or "").strip()
        if not content:
            return jsonify({
                "success": False,
                "error": "Input content cannot be empty. Please provide a message, email, URL, or image with readable text."
            }), 400

        # Validate scan_type
        valid_types = {"text", "email", "url", "job_offer", "screenshot"}
        if scan_type not in valid_types:
            scan_type = "text"

        # 4. Execute multi-signal scam analysis with language support
        analysis_result = analyze_content(content, scan_type=scan_type, language=language)

        if extracted_text:
            analysis_result["extracted_text"] = extracted_text

        # 5. Determine authenticated user (Strict separation: None for guest scans)
        authenticated_user_id = session.get("user_id")

        # Prepare flags and recommendations as JSON strings for MySQL storage
        flags_json = json.dumps(analysis_result.get("detected_flags", []))
        recs_json = json.dumps(analysis_result.get("recommendations", []))

        # Insert scan record into MySQL database
        insert_sql = """
            INSERT INTO scans (
                user_id, scan_type, input_snippet, risk_score,
                risk_level, confidence_score, detected_flags, recommendations
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        scan_id = execute_query(
            insert_sql,
            (
                authenticated_user_id,
                analysis_result["scan_type"],
                analysis_result["input_snippet"],
                analysis_result["risk_score"],
                analysis_result["risk_level"],
                analysis_result["confidence_score"],
                flags_json,
                recs_json,
            ),
            commit=True,
        )

        analysis_result["scan_id"] = scan_id
        analysis_result["is_authenticated"] = bool(authenticated_user_id)

        return jsonify({
            "success": True,
            "data": analysis_result
        }), 200

    except Exception as e:
        logger.error(f"Scan API error: {e}", exc_info=True)
        return jsonify({
            "success": False,
            "error": "An internal error occurred during analysis. Please try again later."
        }), 500


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def get_scan_details(scan_id):
    """Fetch details of a previous scan record for display."""
    try:
        query = "SELECT * FROM scans WHERE id = %s"
        scan = fetch_one(query, (scan_id,))
        if not scan:
            return jsonify({"success": False, "error": "Scan record not found."}), 404

        # If scan is linked to a user, ensure only that user or an admin can inspect it
        user_id = session.get("user_id")
        if scan["user_id"] is not None and scan["user_id"] != user_id:
            return jsonify({"success": False, "error": "Unauthorized access to scan record."}), 403

        # Parse stored JSON columns
        try:
            scan["detected_flags"] = json.loads(scan["detected_flags"])
        except Exception:
            scan["detected_flags"] = []

        try:
            scan["recommendations"] = json.loads(scan["recommendations"])
        except Exception:
            scan["recommendations"] = []

        return jsonify({"success": True, "data": scan}), 200
    except Exception as e:
        logger.error(f"Error fetching scan {scan_id}: {e}")
        return jsonify({"success": False, "error": "Database error retrieving scan."}), 500


# -----------------------------------------------------------------------------
# User Authentication Routes
# -----------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    """User Registration route."""
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validation
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("register.html", username=username, email=email)

        if len(username) < 3 or len(username) > 30:
            flash("Username must be between 3 and 30 characters.", "danger")
            return render_template("register.html", username=username, email=email)

        if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
            flash("Please enter a valid email address.", "danger")
            return render_template("register.html", username=username, email=email)

        if len(password) < 6:
            flash("Password must be at least 6 characters long.", "danger")
            return render_template("register.html", username=username, email=email)

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template("register.html", username=username, email=email)

        # Check existing user
        try:
            existing_user = fetch_one("SELECT id FROM users WHERE username = %s", (username,))
            if existing_user:
                flash("Username is already taken. Please choose another.", "danger")
                return render_template("register.html", username=username, email=email)

            existing_email = fetch_one("SELECT id FROM users WHERE email = %s", (email,))
            if existing_email:
                flash("An account with this email already exists. Please log in.", "danger")
                return render_template("register.html", username=username, email=email)

            # Hash password securely
            password_hash = generate_password_hash(password)

            # Insert new user
            insert_user_sql = """
                INSERT INTO users (username, email, password_hash)
                VALUES (%s, %s, %s)
            """
            new_user_id = execute_query(insert_user_sql, (username, email, password_hash), commit=True)

            # Set user session
            session.clear()
            session["user_id"] = new_user_id
            session["username"] = username
            session["is_admin"] = (username.lower() == "admin")

            flash("Account registered successfully! Welcome to TrustGuard AI.", "success")
            return redirect(url_for("dashboard"))

        except Exception as e:
            logger.error(f"Registration error: {e}", exc_info=True)
            flash("A database error occurred during registration. Please try again.", "danger")
            return render_template("register.html", username=username, email=email)

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """User Login route."""
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        if not identifier or not password:
            flash("Please enter both username/email and password.", "danger")
            return render_template("login.html", identifier=identifier)

        try:
            # Match either username or email
            user = fetch_one(
                "SELECT * FROM users WHERE username = %s OR email = %s",
                (identifier, identifier.lower())
            )

            if user and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["is_admin"] = bool(user.get("is_admin") or user.get("username") == "admin")

                flash(f"Welcome back, {user['username']}!", "success")
                next_page = request.args.get("next") or request.form.get("next")
                if next_page and next_page.startswith("/") and not next_page.startswith("//"):
                    # Validate relative redirect to prevent open redirect vulnerabilities
                    parsed_next = urllib.parse.urlparse(next_page)
                    if not parsed_next.netloc and parsed_next.path.startswith("/"):
                        return redirect(next_page)
                return redirect(url_for("dashboard"))
            else:
                flash("Invalid username/email or password.", "danger")
                return render_template("login.html", identifier=identifier), 401

        except Exception as e:
            logger.error(f"Login error: {e}", exc_info=True)
            flash("A database error occurred while signing in. Please try again.", "danger")
            return render_template("login.html", identifier=identifier)

    return render_template("login.html")


@app.route("/logout")
def logout():
    """User Logout route."""
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login"))


# -----------------------------------------------------------------------------
# Dashboard & Analytics Routes
# -----------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    """User Dashboard displaying personal scan history and statistics."""
    user_id = session.get("user_id")

    try:
        # Fetch user's scans
        scans = fetch_all(
            "SELECT * FROM scans WHERE user_id = %s ORDER BY created_at DESC LIMIT 50",
            (user_id,)
        )

        # Parse JSON fields for template rendering
        for s in scans:
            try:
                s["detected_flags"] = json.loads(s["detected_flags"])
            except Exception:
                s["detected_flags"] = []

        # Compute summary statistics
        total_scans = len(scans)
        high_risk_count = sum(1 for s in scans if s["risk_level"] == "High Risk")
        suspicious_count = sum(1 for s in scans if s["risk_level"] == "Suspicious")
        low_risk_count = sum(1 for s in scans if s["risk_level"] == "Low Risk")

        avg_score = (
            round(sum(s["risk_score"] for s in scans) / total_scans, 1)
            if total_scans > 0
            else 0
        )

        # Breakdown by scan modality
        type_counts = {
            "text": sum(1 for s in scans if s["scan_type"] == "text"),
            "email": sum(1 for s in scans if s["scan_type"] == "email"),
            "url": sum(1 for s in scans if s["scan_type"] == "url"),
            "job_offer": sum(1 for s in scans if s["scan_type"] == "job_offer"),
            "screenshot": sum(1 for s in scans if s["scan_type"] == "screenshot"),
        }

        stats = {
            "total_scans": total_scans,
            "high_risk_count": high_risk_count,
            "suspicious_count": suspicious_count,
            "low_risk_count": low_risk_count,
            "avg_score": avg_score,
            "type_counts": type_counts,
        }

        return render_template("dashboard.html", scans=scans, stats=stats)

    except Exception as e:
        logger.error(f"Dashboard error: {e}", exc_info=True)
        flash("Could not load complete dashboard statistics. Please ensure database is connected.", "danger")
        return render_template("dashboard.html", scans=[], stats={
            "total_scans": 0,
            "high_risk_count": 0,
            "suspicious_count": 0,
            "low_risk_count": 0,
            "avg_score": 0,
            "type_counts": {"text": 0, "email": 0, "url": 0, "job_offer": 0, "screenshot": 0},
        })


@app.route("/api/dashboard/stats")
@login_required
def dashboard_stats_api():
    """API endpoint providing JSON aggregated data for Chart.js."""
    user_id = session.get("user_id")
    try:
        scans = fetch_all(
            "SELECT risk_score, risk_level, scan_type, created_at FROM scans WHERE user_id = %s ORDER BY created_at ASC",
            (user_id,)
        )

        risk_breakdown = {
            "Low Risk": sum(1 for s in scans if s["risk_level"] == "Low Risk"),
            "Suspicious": sum(1 for s in scans if s["risk_level"] == "Suspicious"),
            "High Risk": sum(1 for s in scans if s["risk_level"] == "High Risk"),
        }

        modality_breakdown = {
            "Text / SMS": sum(1 for s in scans if s["scan_type"] == "text"),
            "Email": sum(1 for s in scans if s["scan_type"] == "email"),
            "URL / Web": sum(1 for s in scans if s["scan_type"] == "url"),
            "Job Offer": sum(1 for s in scans if s["scan_type"] == "job_offer"),
            "Screenshot": sum(1 for s in scans if s["scan_type"] == "screenshot"),
        }

        # Trend data: last 15 scans
        recent_trend = [
            {
                "id": idx + 1,
                "score": s["risk_score"],
                "level": s["risk_level"],
                "date": s["created_at"].strftime("%b %d, %H:%M") if hasattr(s["created_at"], "strftime") else str(s["created_at"])
            }
            for idx, s in enumerate(scans[-15:])
        ]

        return jsonify({
            "success": True,
            "risk_breakdown": risk_breakdown,
            "modality_breakdown": modality_breakdown,
            "recent_trend": recent_trend,
        }), 200

    except Exception as e:
        logger.error(f"Stats API error: {e}")
        return jsonify({"success": False, "error": "Database error loading statistics."}), 500


# -----------------------------------------------------------------------------
# Community Scam Reporting & Moderation Routes
# -----------------------------------------------------------------------------
@app.route("/community")
def community_reports_page():
    """
    Public Community Scam Awareness & Reports Feed.
    Displays approved scam reports for public education while filtering out pending submissions.
    """
    category_filter = request.args.get("category", "all").strip()

    try:
        base_query = """
            SELECT r.id, r.user_id, r.category, r.scam_type, r.evidence_snippet,
                   r.description, r.indicators, r.status, r.created_at,
                   u.username as reporter_username
            FROM community_reports r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.status = 'approved'
        """
        params = []
        if category_filter and category_filter != "all":
            base_query += " AND r.category = %s"
            params.append(category_filter)

        base_query += " ORDER BY r.created_at DESC LIMIT 50"
        raw_reports = fetch_all(base_query, tuple(params) if params else None) or []

        reports = []
        for r in raw_reports:
            # Parse indicators JSON safely
            try:
                r["indicators_list"] = json.loads(r["indicators"]) if r.get("indicators") else []
            except Exception:
                r["indicators_list"] = []

            # Privacy preservation: Never display emails, passwords, or sensitive data
            if r.get("user_id") and r.get("reporter_username"):
                r["author_label"] = f"Community Member (@{r['reporter_username']})"
                r["is_guest"] = False
            else:
                r["author_label"] = "Anonymous Contributor"
                r["is_guest"] = True

            reports.append(r)

        # Available categories for filtering
        categories = [
            "All",
            "Phishing / SMS",
            "Fake Job Offer",
            "Financial / Crypto Scam",
            "Deceptive URL",
            "Impersonation Scam",
            "Other"
        ]

        # Check if current user is admin to show moderation link
        is_admin = False
        user_id = session.get("user_id")
        if user_id:
            u_row = fetch_one("SELECT is_admin, username FROM users WHERE id = %s", (user_id,))
            is_admin = bool(u_row and (u_row.get("is_admin") or u_row.get("username") == "admin"))

        return render_template(
            "community.html",
            reports=reports,
            active_category=category_filter,
            categories=categories,
            is_admin=is_admin
        )

    except Exception as e:
        logger.error(f"Error fetching community reports: {e}", exc_info=True)
        flash("Could not retrieve community reports at this time.", "danger")
        return render_template("community.html", reports=[], active_category="all", categories=["All"], is_admin=False)


@app.route("/api/community/reports", methods=["POST"])
def submit_community_report():
    """
    Asynchronous Community Report Submission Endpoint.
    Validates user input, prevents spam, attributes authenticated vs guest reports,
    and places submissions in 'pending' status for moderation review.
    """
    try:
        # 1. Parse JSON or Form payload
        if request.is_json:
            data = request.get_json() or {}
        else:
            data = request.form.to_dict()

        category = (data.get("category") or "").strip()
        scam_type = (data.get("scam_type") or "text").strip().lower()
        evidence_snippet = (data.get("evidence_snippet") or data.get("evidence") or "").strip()
        description = (data.get("description") or "").strip()

        # 2. Input Validation
        if not category:
            return jsonify({"success": False, "error": "Please select a scam report category."}), 400
        if len(category) > 50:
            return jsonify({"success": False, "error": "Category name exceeds maximum allowed length."}), 400

        valid_scam_types = {"text", "email", "url", "job_offer", "screenshot", "other"}
        if scam_type not in valid_scam_types:
            scam_type = "text"

        if not evidence_snippet or len(evidence_snippet) < 5:
            return jsonify({
                "success": False,
                "error": "Please provide the suspicious communication text, message snippet, or URL (minimum 5 characters)."
            }), 400
        if len(evidence_snippet) > 3000:
            return jsonify({"success": False, "error": "Suspicious evidence snippet exceeds 3,000 characters."}), 400

        if not description or len(description) < 10:
            return jsonify({
                "success": False,
                "error": "Please explain why you believe this communication is suspicious (minimum 10 characters)."
            }), 400
        if len(description) > 2000:
            return jsonify({"success": False, "error": "Description exceeds 2,000 characters."}), 400

        # Safety & Non-Defamation Guard: Ensure users report suspicious communications rather than individuals
        defamation_patterns = [r"\bhe is a thief\b", r"\bshe is a scammer\b", r"\bkill\b", r"\bhate\b"]
        for p in defamation_patterns:
            if re.search(p, description, re.IGNORECASE):
                return jsonify({
                    "success": False,
                    "error": "Community submissions must describe suspicious communication patterns neutrally. Personal accusations or derogatory remarks are not permitted."
                }), 400

        # 3. Rate-Limiting & Anti-Spam (15-second per-session cooldown)
        now_ts = time.time()
        last_submit = session.get("last_report_submit", 0)
        if (now_ts - last_submit) < 15:
            return jsonify({
                "success": False,
                "error": "You are submitting reports too quickly. Please wait a few seconds before trying again."
            }), 429

        # Duplicate check: prevent submitting exact identical evidence within 24 hours
        dup_row = fetch_one(
            "SELECT id FROM community_reports WHERE evidence_snippet = %s AND created_at >= NOW() - INTERVAL 1 DAY LIMIT 1",
            (evidence_snippet,)
        )
        if dup_row:
            return jsonify({
                "success": False,
                "error": "A community report with this exact suspicious evidence has already been submitted in the last 24 hours."
            }), 409

        # 4. User Attribution (Strict separation: None for guests)
        authenticated_user_id = session.get("user_id")

        # 5. Automatically extract threat indicators if present
        indicators_list = []
        try:
            # Run heuristic check to populate helpful educational tags
            from scanner import analyze_content
            auto_analysis = analyze_content(evidence_snippet, scan_type=scam_type)
            indicators_list = [f["flag"] for f in auto_analysis.get("detected_flags", [])][:4]
        except Exception as scan_err:
            logger.debug(f"Indicator extraction skipped: {scan_err}")

        # 6. Save in MySQL with status 'pending' (never publicly approved immediately)
        insert_sql = """
            INSERT INTO community_reports (
                user_id, category, scam_type, evidence_snippet,
                description, indicators, status
            ) VALUES (%s, %s, %s, %s, %s, %s, 'pending')
        """
        report_id = execute_query(
            insert_sql,
            (
                authenticated_user_id,
                category,
                scam_type,
                evidence_snippet,
                description,
                json.dumps(indicators_list),
            ),
            commit=True
        )

        session["last_report_submit"] = now_ts

        return jsonify({
            "success": True,
            "message": "Thank you! Your scam report has been submitted to the community queue. To maintain trust and avoid false accusations, submissions are held in Pending review before public listing.",
            "report_id": report_id,
            "status": "pending"
        }), 201

    except Exception as e:
        logger.error(f"Error submitting community report: {e}", exc_info=True)
        return jsonify({"success": False, "error": "An error occurred while saving your report. Please try again."}), 500


@app.route("/community/moderate")
@admin_required
def community_moderate_page():
    """
    Administrative Moderation Dashboard.
    Allows designated moderators/admins to review and approve/reject pending community reports.
    """
    try:
        pending_reports = fetch_all("""
            SELECT r.id, r.user_id, r.category, r.scam_type, r.evidence_snippet,
                   r.description, r.indicators, r.status, r.created_at,
                   u.username as reporter_username, u.email as reporter_email
            FROM community_reports r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.status = 'pending'
            ORDER BY r.created_at ASC
        """) or []

        for r in pending_reports:
            try:
                r["indicators_list"] = json.loads(r["indicators"]) if r.get("indicators") else []
            except Exception:
                r["indicators_list"] = []

        return render_template("moderate.html", reports=pending_reports)

    except Exception as e:
        logger.error(f"Error loading moderation queue: {e}", exc_info=True)
        flash("Could not load moderation queue.", "danger")
        return redirect(url_for("community_reports_page"))


@app.route("/api/community/reports/<int:report_id>/status", methods=["POST"])
@admin_required
def moderate_report_status(report_id):
    """
    Protected Moderation Action Endpoint.
    Approves or rejects a submitted report.
    """
    try:
        data = request.get_json() or {}
        new_status = data.get("status")

        if new_status not in ("approved", "rejected"):
            return jsonify({"success": False, "error": "Invalid status. Must be 'approved' or 'rejected'."}), 400

        # Check existence
        existing = fetch_one("SELECT id, status FROM community_reports WHERE id = %s", (report_id,))
        if not existing:
            return jsonify({"success": False, "error": "Report not found."}), 404

        execute_query(
            "UPDATE community_reports SET status = %s WHERE id = %s",
            (new_status, report_id),
            commit=True
        )

        return jsonify({
            "success": True,
            "message": f"Report #{report_id} has been {new_status}.",
            "report_id": report_id,
            "status": new_status,
            "new_status": new_status
        }), 200

    except Exception as e:
        logger.error(f"Moderation update error: {e}", exc_info=True)
        return jsonify({"success": False, "error": "Failed to update report status."}), 500


# -----------------------------------------------------------------------------
# Error Handlers
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found_error(error):
    return render_template(
        "base.html",
        page_title="Page Not Found",
        custom_content="<div class='container py-5 text-center'><h2>404 — Page Not Found</h2><p class='text-muted'>The requested page does not exist.</p><a href='/' class='btn btn-primary mt-3'>Return to Scanner</a></div>"
    ), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template(
        "base.html",
        page_title="Internal Server Error",
        custom_content="<div class='container py-5 text-center'><h2>500 — Server Error</h2><p class='text-muted'>An unexpected error occurred. Please try again later.</p><a href='/' class='btn btn-primary mt-3'>Return to Home</a></div>"
    ), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=Config.DEBUG)
