# TrustGuard AI

### An Intelligent Digital Trust and Scam Detection Platform

> Final-Year B.Sc. Computer Science Project

TrustGuard AI is a web application that helps people evaluate whether a text message, email, URL, job offer, or screenshot could be a scam. It combines a trained machine-learning classifier, rule-based heuristic pattern detection, and local URL forensics into a single risk score. Users do not need an account to run a scan — the tool is accessible to everyone immediately from the homepage.

---

## Table of Contents

1. [Problem Statement and Objectives](#1-problem-statement-and-objectives)
2. [Main Features](#2-main-features)
3. [Screenshots](#3-screenshots)
4. [Technology Stack](#4-technology-stack)
5. [System Architecture and Request Flow](#5-system-architecture-and-request-flow)
6. [Project Structure](#6-project-structure)
7. [Prerequisites (Windows)](#7-prerequisites-windows)
8. [Installation and Virtual-Environment Setup](#8-installation-and-virtual-environment-setup)
9. [Environment-Variable Configuration](#9-environment-variable-configuration)
10. [MySQL Database Setup](#10-mysql-database-setup)
11. [Starting the Application](#11-starting-the-application)
12. [Running the Test Scripts](#12-running-the-test-scripts)
13. [Machine-Learning Model](#13-machine-learning-model)
14. [OCR and Tesseract Configuration](#14-ocr-and-tesseract-configuration)
15. [Security Considerations](#15-security-considerations)
16. [Current Limitations](#16-current-limitations)
17. [Possible Future Improvements](#17-possible-future-improvements)
18. [Academic Project Disclaimer](#18-academic-project-disclaimer)

---

## 1. Problem Statement and Objectives

Digital scams — phishing emails, SMS fraud, fake job offers, and deceptive URLs — are among the most common threats that individuals face online. Victims often lack the technical knowledge to identify subtle warning signs before they share personal information or transfer money.

**This project addresses that gap by providing a free, accessible tool that:**

- Analyses suspicious communications and assigns a risk score from 0 to 100.
- Explains exactly which patterns triggered concern (e.g. urgent deadlines, credential requests, untraceable payment demands).
- Provides practical safety recommendations based on the detected risk level.
- Supports English, Spanish, French, and German content.
- Extracts and analyses text directly from screenshots using OCR, so users can upload images of suspicious messages without retyping them.
- Allows the community to submit and view approved scam reports for public awareness.

**Project objectives:**

1. Design and implement a hybrid scam-detection engine combining a trained text classifier with deterministic heuristic rules and URL pattern analysis.
2. Build a full-stack web application with a clean, accessible interface using Flask, HTML, CSS, and JavaScript.
3. Integrate a MySQL relational database for user accounts, scan history, and community reports.
4. Implement role-based access control for user and administrator functions.
5. Provide multilingual detection capability for four supported languages.
6. Demonstrate the system through a comprehensive test suite covering all major features.

---

## 2. Main Features

### Scanning Modes

| Mode | Description |
|------|-------------|
| **Text / SMS** | Paste any suspicious message, SMS, or direct message |
| **Email** | Paste email body content for phishing and social-engineering analysis |
| **Suspicious URL** | Enter a URL for local forensic checks (no external API required) |
| **Job / Internship Offer** | Detect fake recruitment scams and upfront-fee requests |
| **Screenshot Upload** | Upload a PNG, JPG, JPEG, or WEBP image — text is extracted by OCR and then analysed |

### Detection Engine

- **ML Classifier (English):** A TF-IDF vectoriser combined with the best-performing classifier (selected by F1 score between Logistic Regression and Multinomial Naive Bayes), trained on the UCI SMS Spam Collection dataset. Contributes 45% of the composite risk score for English content.
- **Heuristic Pattern Rules:** Six rule categories covering high-urgency language, untraceable payment requests (cryptocurrency, gift cards, wire transfers), credential and OTP demands, job-scam indicators, unsolicited prize claims, and impersonation of authority or support teams. Weighted by severity.
- **Local URL Forensics:** Seven structural checks applied to any URL found in the content: unencrypted HTTP, bare IP-address hostname, obfuscated `@` character in the URL authority, high-risk top-level domains (`.xyz`, `.tk`, `.top`, `.click`, and others), URL shortening services, brand-name spoofing in subdomains, and excessive subdomain depth. These checks do not call any external API.

### Multilingual Support

TrustGuard AI applies a tiered analysis strategy depending on the language of the content:

| Tier | Languages | Analysis Approach |
|------|-----------|-------------------|
| Tier 1 | English | Full hybrid: TF-IDF ML classifier + English heuristic rules + URL forensics |
| Tier 2 | Spanish, French, German | Localised heuristic rule sets translated for each language + URL forensics. The English ML model is intentionally bypassed to avoid inaccurate cross-lingual predictions. |
| Tier 3 | All other languages | URL forensics only, with an honest advisory note explaining the limitation |

Language can be set manually via a dropdown selector or detected automatically from the content.

### User Accounts and Dashboard

- Register and log in with a username or email address.
- Passwords are hashed using Werkzeug's `scrypt`-based implementation and are never stored in plaintext.
- The personal dashboard displays up to 50 recent scans, five summary statistics cards, a risk-level doughnut chart, and a scan-type bar chart (both powered by Chart.js).
- Each historical scan can be expanded in a detail modal to view the full flag list and recommendations.

### Community Scam Reporting

- Any visitor (guest or registered user) can submit a scam report with a category, evidence snippet, and description.
- All submissions start in **pending** status and are never immediately visible to the public.
- An administrator reviews pending reports and approves or rejects them.
- Only approved reports appear on the public community feed, which supports category filtering.
- Anti-spam controls: a 15-second session cooldown between submissions and a 24-hour duplicate-evidence check.
- A defamation guard rejects submissions containing personal accusations or hostile language.

### Guest Scanning

No account is required. Any visitor can run a scan from the homepage. Guest scans are stored in the database with `user_id = NULL` and are not linked to any account.

---

## 3. Screenshots

### Homepage — Scanner Interface

![Homepage](project%20screenshots/Homepage.png)

### Text Message Scan Result

![Text Scan](project%20screenshots/text.png)

### URL Analysis Result

![URL Analysis](project%20screenshots/URL.png)

### Fake Internship / Job Offer Detection

![Fake Internship Detection](project%20screenshots/FakeInternship.png)

### Screenshot OCR Scan

![Screenshot OCR Scan](project%20screenshots/screenshot.png)

### Language Selector — Multilingual Mode

![Language Selector](project%20screenshots/languageselector.png)

### Spanish Language Scam Detection

![Spanish Detector](project%20screenshots/spanishdetector.png)

### Login Page

![Login](project%20screenshots/Login.png)

### Registration Page

![Registration](project%20screenshots/registration.png)

### Security Dashboard

![Dashboard](project%20screenshots/dashboard.png)

![Dashboard Charts](project%20screenshots/dashboard1.png)

### Community Scam Reports Feed

![Community Page](project%20screenshots/community%20page.png)

### Submitting a Community Report

![Submitting Report](project%20screenshots/submittingform.png)

![Report Submitted](project%20screenshots/successfullysubmited.png)

### Admin Moderation Panel

![Moderation Page](project%20screenshots/moderationpage.png)

### Approved Report on Public Feed

![Approved Report](project%20screenshots/approvedreport.png)

---

## 4. Technology Stack

| Category | Technology | Purpose |
|----------|-----------|---------|
| **Backend** | Python 3.x, Flask ≥ 3.0 | Web framework and application server |
| **Database** | MySQL 8.0+, mysql-connector-python, PyMySQL | Persistent storage for users, scans, and reports |
| **Machine Learning** | scikit-learn ≥ 1.4, pandas ≥ 2.0, numpy ≥ 1.26, joblib ≥ 1.3 | TF-IDF vectoriser and text classifier |
| **OCR** | Tesseract OCR (system binary), pytesseract ≥ 0.3.10, Pillow ≥ 10.0 | Text extraction from uploaded images |
| **Authentication** | Werkzeug (Flask dependency) | Password hashing and verification |
| **Configuration** | python-dotenv ≥ 1.0 | Loading environment variables from `.env` |
| **Frontend** | HTML5, CSS3, Vanilla JavaScript | UI markup, styling, and interactivity |
| **Charts** | Chart.js 4.4 (CDN) | Dashboard doughnut and bar charts |
| **Icons** | Font Awesome 6 (CDN) | UI icons |

---

## 5. System Architecture and Request Flow

TrustGuard AI follows a conventional server-rendered and API-driven architecture. There are no external third-party APIs; all analysis is performed locally.

```
┌────────────────────────────────────────────────────────────────┐
│                        Browser (Client)                        │
│  HTML / CSS / JS (scan.js, dashboard.js, community.js)         │
└──────────────────────────────┬─────────────────────────────────┘
                               │ HTTP / fetch()
┌──────────────────────────────▼─────────────────────────────────┐
│                      Flask Application (app.py)                │
│                                                                │
│  Routes:                                                       │
│  GET  /                    — Homepage (scanner interface)      │
│  POST /api/scan            — Scan endpoint (JSON or multipart) │
│  GET  /api/scan/<id>       — Fetch stored scan details         │
│  GET  /api/ocr/status      — Check Tesseract availability      │
│  GET  /api/dashboard/stats — Chart.js data for dashboard       │
│  POST /api/community/reports          — Submit scam report     │
│  POST /api/community/reports/<id>/status — Moderate report     │
│  GET  /dashboard           — Personal scan history (auth)      │
│  GET  /community           — Public approved reports feed      │
│  GET  /community/moderate  — Admin moderation panel            │
│  POST /register, /login, GET /logout                           │
└──────┬──────────────────────┬──────────────────────────────────┘
       │                      │
┌──────▼──────┐      ┌────────▼─────────────────────────────────┐
│  ocr.py     │      │  scanner.py — Analysis Engine            │
│             │      │                                          │
│  Pillow     │      │  1. Language detection (auto or manual)  │
│  validate   │      │  2. Heuristic pattern matching           │
│  pytesseract│      │  3. URL forensic checks (7 rules)        │
│  extract    │      │  4. ML inference (English Tier 1 only)   │
│  cleanup    │      │  5. Score calculation and categorisation │
└──────┬──────┘      └────────┬─────────────────────────────────┘
       │                      │
       └──────────┬───────────┘
                  │
┌─────────────────▼──────────────────────────────────────────────┐
│                    db.py — Database Layer                      │
│  execute_query / fetch_one / fetch_all / check_connection      │
│  init_db() applies schema.sql on startup                       │
└─────────────────┬──────────────────────────────────────────────┘
                  │
┌─────────────────▼──────────────────────────────────────────────┐
│                 MySQL 8.0 — trustguard_db                      │
│  Tables: users | scans | community_reports                     │
└────────────────────────────────────────────────────────────────┘
```

**Text scan flow:**
Browser → `POST /api/scan` → `scanner.py:analyze_content()` → ML + heuristics + URL checks → `db.py` saves result → JSON response rendered by `scan.js`.

**Screenshot scan flow:**
Browser → `POST /api/scan` (multipart) → `ocr.py` validates and extracts text → temp file deleted → extracted text passed to `scanner.py:analyze_content()` → result saved and returned.

---

## 6. Project Structure

```
TrustGuard AI project/
│
├── app.py                    # Flask application — all routes and request handling
├── config.py                 # Configuration class loaded from .env
├── db.py                     # MySQL database helpers (execute, fetch, init)
├── scanner.py                # Scam analysis engine (ML + heuristics + URL forensics)
├── ocr.py                    # Tesseract OCR service (image validation and extraction)
├── run.py                    # Development server entry point
├── schema.sql                # MySQL schema (CREATE TABLE IF NOT EXISTS)
├── requirements.txt          # Python package dependencies
│
├── .env                      # Local secrets — never committed to Git
├── .env.example              # Placeholder template — safe to commit
├── .gitignore                # Excludes .env, __pycache__, uploads, logs, etc.
│
├── ml/
│   ├── model.pkl             # Trained classifier artifact (157 KB)
│   ├── vectorizer.pkl        # Fitted TF-IDF vectoriser (186 KB)
│   ├── dataset.csv           # Training dataset — NOT included in this repository (see Section 13)
│   ├── train.py              # Model training and evaluation pipeline
│   └── download_dataset.py   # Dataset download and preparation utility
│
├── templates/
│   ├── base.html             # Shared page layout and navigation
│   ├── index.html            # Homepage with scanner interface
│   ├── dashboard.html        # Personal scan history and charts
│   ├── community.html        # Public community scam reports feed
│   ├── moderate.html         # Admin moderation panel
│   ├── login.html            # Login form
│   └── register.html         # Registration form
│
├── static/
│   ├── css/style.css         # All custom styles
│   └── js/
│       ├── scan.js           # Scanner UI, API calls, and result rendering
│       ├── dashboard.js      # Chart.js dashboard charts and scan detail modal
│       └── community.js      # Report submission and moderation interactions
│
├── project screenshots/      # Application screenshots (16 PNG files)
├── test_assets/              # Static assets used by the test suite
│   └── phishing_screenshot.png
│
├── uploads/                  # Temporary OCR upload directory (auto-created)
│                             # Files are deleted immediately after processing
│
├── test_db.py                # Database connectivity and CRUD tests
├── test_app.py               # Full-stack Flask integration tests (13 assertions)
├── test_ocr.py               # Screenshot OCR verification tests (14 assertions)
└── test_community_and_multilingual.py  # Community + multilingual tests (34 assertions)
```

---

## 7. Prerequisites (Windows)

Before setting up the project, install the following software on your machine:

### Python 3.10 or later
Download from [python.org](https://www.python.org/downloads/). During installation, check **"Add Python to PATH"**.

Verify the installation:
```
python --version
```

### MySQL 8.0 or later
Download MySQL Community Server from [dev.mysql.com](https://dev.mysql.com/downloads/mysql/). During setup, set a root password and note it down — you will need it later.

Verify the installation:
```
mysql --version
```

### Tesseract OCR
Download the Windows installer from [UB-Mannheim/tesseract](https://github.com/UB-Mannheim/tesseract/wiki) (the official Windows build maintained by UB Mannheim).

- The default installation path is `C:\Program Files\Tesseract-OCR\tesseract.exe`.
- If you install to a different location, note the full path — you will need to set it in `.env`.

Verify the installation:
```
"C:\Program Files\Tesseract-OCR\tesseract.exe" --version
```

> **Note on OCR language support:** The default Tesseract installer includes only the English (`eng`) language model. If you want to scan screenshots in Spanish, French, or German, you need to install the corresponding Tesseract language data (`.traineddata` files). The application gracefully falls back to English OCR if the requested language model is not installed.

### Git (optional, for cloning)
Download from [git-scm.com](https://git-scm.com/).

---

## 8. Installation and Virtual-Environment Setup

**Step 1 — Clone or download the repository**

```bash
git clone https://github.com/gauriadnav/trustguard-ai.git
cd trustguard-ai
```

Or download and extract the ZIP, then open a terminal in the project folder.

**Step 2 — Create a Python virtual environment**

A virtual environment keeps the project's dependencies separate from your global Python installation.

```bash
python -m venv venv
```

**Step 3 — Activate the virtual environment**

```bash
venv\Scripts\activate
```

You should see `(venv)` at the start of your terminal prompt, confirming the environment is active.

**Step 4 — Install the required packages**

```bash
pip install -r requirements.txt
```

This installs all ten dependencies listed in `requirements.txt`:

| Package | Purpose |
|---------|---------|
| Flask ≥ 3.0 | Web framework |
| mysql-connector-python ≥ 8.0 | MySQL connectivity |
| PyMySQL ≥ 1.1 | MySQL driver |
| scikit-learn ≥ 1.4 | ML classifier and TF-IDF vectoriser |
| pandas ≥ 2.0 | Dataset loading and manipulation |
| numpy ≥ 1.26 | Numerical computation |
| joblib ≥ 1.3 | Loading serialised model artifacts |
| Pillow ≥ 10.0 | Image loading and validation |
| pytesseract ≥ 0.3.10 | Python wrapper for Tesseract OCR |
| python-dotenv ≥ 1.0 | Reading environment variables from `.env` |

---

## 9. Environment-Variable Configuration

The application reads all sensitive configuration from a `.env` file in the project root. This file is listed in `.gitignore` and must **never** be uploaded to GitHub.

**Step 1 — Copy the example file**

```bash
copy .env.example .env
```

**Step 2 — Open `.env` in a text editor and fill in your values**

The file contains the following variables:

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | A long, random string used to sign Flask sessions. The application will refuse to start if this is missing or empty. | **Yes** |
| `DB_HOST` | MySQL server address. Use `127.0.0.1` for a local installation. | Yes |
| `DB_PORT` | MySQL port. The default is `3306`. | Yes |
| `DB_USER` | MySQL username. | Yes |
| `DB_PASSWORD` | MySQL password for the user above. | Yes |
| `DB_NAME` | Database name. The schema creates `trustguard_db` automatically. | Yes |
| `MAX_CONTENT_LENGTH` | Maximum upload size in bytes. The default is `5242880` (5 MB). | Optional |
| `UPLOAD_FOLDER` | Folder name for temporary OCR uploads. The default is `uploads`. | Optional |
| `TESSERACT_CMD` | Full path to the Tesseract executable. Required on Windows if Tesseract is not on the system PATH. | Optional |
| `FLASK_DEBUG` | Set to `True` to enable debug mode during local development. Leave unset or set to `False` for all other environments. | Optional |

**Generating a secure SECRET_KEY**

Open a Python terminal and run:

```python
import secrets
print(secrets.token_hex(32))
```

Copy the output and paste it as the value of `SECRET_KEY` in your `.env` file.

**Example `.env` structure (do not use these placeholder values):**

```
SECRET_KEY=replace-this-with-a-long-random-string
DB_HOST=127.0.0.1
DB_PORT=3306
DB_USER=root
DB_PASSWORD=your_mysql_root_password
DB_NAME=trustguard_db
TESSERACT_CMD=C:\Program Files\Tesseract-OCR\tesseract.exe
FLASK_DEBUG=True
```

> ⚠️ Never commit your actual `.env` file to a public repository. It contains your database credentials and secret key.

---

## 10. MySQL Database Setup

### Automatic Setup (recommended)

The database, tables, and indexes are created automatically when the application starts for the first time. The `db.py` module runs the `schema.sql` file using `CREATE TABLE IF NOT EXISTS` statements, so it is safe to restart the application without losing data.

You only need to make sure that the MySQL server is running and that the credentials in your `.env` file are correct.

### Manual Setup (alternative)

If you prefer to create the database manually before starting the application:

**Log in to MySQL:**
```bash
mysql -u root -p
```

**Apply the schema:**
```bash
mysql -u root -p < schema.sql
```

### What the Schema Creates

The schema (`schema.sql`) creates the database `trustguard_db` and three tables:

**`users`** — stores registered accounts

| Column | Type | Notes |
|--------|------|-------|
| `id` | INT AUTO_INCREMENT | Primary key |
| `username` | VARCHAR(50) UNIQUE | |
| `email` | VARCHAR(100) UNIQUE | |
| `password_hash` | VARCHAR(255) | scrypt hash — never plaintext |
| `is_admin` | TINYINT(1) | 0 = standard user, 1 = administrator |
| `created_at` | TIMESTAMP | |

**`scans`** — stores analysis results for registered users and guests

| Column | Type | Notes |
|--------|------|-------|
| `id` | INT AUTO_INCREMENT | Primary key |
| `user_id` | INT NULL | NULL for guest scans |
| `scan_type` | ENUM | text, email, url, screenshot, job_offer |
| `input_snippet` | VARCHAR(255) | First 200 characters of the input |
| `risk_score` | INT | 0–100 |
| `risk_level` | ENUM | Low Risk, Suspicious, High Risk |
| `confidence_score` | DECIMAL(4,2) | |
| `detected_flags` | TEXT | JSON array of detected indicators |
| `recommendations` | TEXT | JSON array of safety advice |
| `created_at` | TIMESTAMP | |

**`community_reports`** — stores user-submitted scam reports

| Column | Type | Notes |
|--------|------|-------|
| `id` | INT AUTO_INCREMENT | Primary key |
| `user_id` | INT NULL | NULL for guest submissions |
| `category` | VARCHAR(50) | Report category |
| `scam_type` | VARCHAR(30) | Scan modality of the reported content |
| `evidence_snippet` | TEXT | Submitted suspicious text |
| `description` | TEXT | User explanation |
| `indicators` | TEXT | JSON array of auto-detected flags |
| `status` | ENUM | pending, approved, rejected |
| `created_at` | TIMESTAMP | |

### Creating an Administrator Account

After registering a user account through the web interface, you can promote it to administrator by updating the database directly:

```sql
USE trustguard_db;
UPDATE users SET is_admin = 1 WHERE username = 'your_username';
```

Alternatively, any account with the username `admin` is automatically treated as an administrator by the application.

---

## 11. Starting the Application

Make sure your virtual environment is active and MySQL is running, then run:

```bash
python run.py
```

You should see output similar to:

```
============================================================
 TrustGuard AI — Digital Trust & Scam Detection Platform
 Starting local server on http://127.0.0.1:5000 (Debug: False)
============================================================
```

Open your browser and navigate to **http://127.0.0.1:5000**.

**If the application fails to start, check the following:**

| Error message | Likely cause |
|---------------|-------------|
| `RuntimeError: [TrustGuard AI] SECRET_KEY is not set` | `SECRET_KEY` is missing from `.env` |
| `mysql.connector.errors.InterfaceError` | MySQL is not running, or `DB_PASSWORD` is incorrect |
| `ModuleNotFoundError` | Virtual environment is not active, or `pip install -r requirements.txt` was not run |

---

## 12. Running the Test Scripts

The project includes four test scripts that verify different parts of the application. Each script prints a pass/fail result for every assertion. All tests require a running MySQL instance with the correct credentials in `.env`, and the test for OCR requires Tesseract to be installed.

> **Important:** The test scripts create temporary records in the database during testing and clean them up automatically when the tests complete. They do not permanently modify your data.

```bash
# Test 1: MySQL connectivity, schema initialisation, and scan record CRUD
python test_db.py

# Test 2: Full-stack Flask integration (homepage, guest and authenticated scans,
#          registration, password hashing, dashboard, session management)
python test_app.py

# Test 3: Screenshot OCR pipeline (image validation, file-type rejection,
#          corrupted-image handling, temp-file cleanup, live Tesseract execution)
python test_ocr.py

# Test 4: Community reporting and multilingual analysis
#          (input validation, rate limiting, duplicate detection, moderation RBAC,
#          language detection, Tier 1/2/3 analysis, URL forensics, OCR fallback)
python test_community_and_multilingual.py
```

Expected outcome when everything is configured correctly:

| Script | Assertions |
|--------|-----------|
| `test_db.py` | All steps pass |
| `test_app.py` | 13 / 13 |
| `test_ocr.py` | 14 / 14 |
| `test_community_and_multilingual.py` | 34 / 34 |

> If `test_ocr.py` or `test_community_and_multilingual.py` report an exit code of 1 from PowerShell but show all `[PASS]` lines, this is a known PowerShell behaviour: log-level messages printed to stderr (such as `WARNING:` from Pillow or `INFO:` from the Tesseract fallback) cause PowerShell to report a non-zero exit code even though all test assertions passed.

---

## 13. Machine-Learning Model

### Dataset

The ML model is trained on the **UCI SMS Spam Collection** dataset, a widely used benchmark in text classification research.

> **Note:** `ml/dataset.csv` is **not included** in this public repository because its redistribution terms have not yet been verified. The pre-trained model and vectoriser artifacts (`ml/model.pkl` and `ml/vectorizer.pkl`) are included, so the application runs without the dataset. You only need the dataset if you want to retrain the model — see the retraining instructions below.
>
> Before redistributing `ml/dataset.csv` or any derivative of it, please review the applicable terms at the [UCI Machine Learning Repository dataset page](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) and credit the original authors: Almeida, T.A. and Gómez Hidalgo, J.M. (2012).

The prepared dataset contains **5,574 labelled messages** with the following distribution:

| Class | Count | Percentage |
|-------|-------|------------|
| Legitimate (ham) | 4,827 | 86.6% |
| Scam (spam) | 747 | 13.4% |

Each record has three columns: `label` (0 or 1), `label_text` (ham or spam), and `text` (the message content).

### Training Approach

The training pipeline is implemented in `ml/train.py`:

1. **Text feature extraction:** A `TfidfVectorizer` is fitted with up to 5,000 features, using unigrams and bigrams, English stop-word removal, and sublinear term-frequency scaling.
2. **Model selection:** Both Logistic Regression and Multinomial Naive Bayes are trained and evaluated on a stratified 80/20 train-test split. The model with the higher F1 score on the held-out test set is selected automatically.
3. **Serialisation:** The selected model and vectoriser are saved to `ml/model.pkl` and `ml/vectorizer.pkl` using `joblib`.

### Pre-trained Artifacts

The trained artifacts (`model.pkl` and `vectorizer.pkl`) are included in this repository. They are loaded by `scanner.py` using lazy initialisation — they are loaded once on the first English-language scan and cached for all subsequent requests.

### Retraining the Model

The pre-trained artifacts (`model.pkl` and `vectorizer.pkl`) are included in the repository, so **retraining is not required** to run the application. If you wish to retrain the model from scratch:

**Step 1 — Download the dataset**

Run the included download script, which fetches the SMS Spam Collection directly from the official UCI repository, validates its contents, and writes `ml/dataset.csv`:

```bash
python ml/download_dataset.py
```

The script attempts the primary UCI source first and falls back to a mirror automatically if the primary is unavailable. It requires an internet connection, and `pandas` must be installed (included in `requirements.txt`).

> Before redistributing `ml/dataset.csv`, review the applicable terms at the [UCI dataset page](https://archive.ics.uci.edu/dataset/228/sms+spam+collection).

**Step 2 — Retrain and evaluate the model**

```bash
python ml/train.py
```

The training script prints accuracy, precision, recall, F1 score, and a confusion matrix for both Logistic Regression and Multinomial Naive Bayes, selects the best model by F1 score, and overwrites `ml/model.pkl` and `ml/vectorizer.pkl`.

### How the Score Is Calculated

For **English content** (Tier 1):

```
Composite Score = (0.45 × ML probability × 100) + (0.55 × min(Heuristic + URL penalties × 1.5, 100))
```

A safety floor ensures that content with severe indicators (credential requests, bare IP addresses, or untraceable payment demands) always receives a minimum score that reflects high suspicion, even if the ML probability alone is low.

For **Spanish, French, and German content** (Tier 2), the composite score is based entirely on the localised heuristic rules and URL forensic checks. The English ML model is not applied.

For **other languages** (Tier 3), only URL forensic checks contribute to the score, and the result is accompanied by an explanatory note.

> **Risk score interpretation:** The score is a probabilistic indicator based on algorithmic pattern recognition. A low score does not guarantee that content is safe, and a high score does not guarantee that it is fraudulent. Always verify independently before sharing sensitive information or making payments.

---

## 14. OCR and Tesseract Configuration

### How OCR Works

When a user uploads a screenshot, the application:

1. Validates the file extension (PNG, JPG, JPEG, or WEBP only).
2. Verifies image integrity using Pillow.
3. Saves the file temporarily to the `uploads/` folder with a unique random filename.
4. Runs `pytesseract.image_to_string()` to extract readable text.
5. Deletes the temporary file immediately — whether the extraction succeeds or fails.
6. Passes the extracted text to the scam analysis engine.

### Locating Tesseract

The application resolves the Tesseract executable in this order:

1. The path set in `TESSERACT_CMD` in your `.env` file.
2. The system `PATH` (automatic on Linux and macOS if Tesseract is installed via a package manager).
3. Common Windows installation directories (checked automatically as a fallback).

If Tesseract cannot be found, the `/api/ocr/status` endpoint will report `available: false`, and any screenshot upload will return a clear error message.

### Checking OCR Status

Once the application is running, you can verify that Tesseract was detected correctly by visiting:

```
http://127.0.0.1:5000/api/ocr/status
```

A successful response looks like:

```json
{
  "available": true,
  "path_or_message": "C:\\Program Files\\Tesseract-OCR\\tesseract.exe"
}
```

### OCR Language Support

By default, only the English (`eng`) Tesseract language model is installed. If a user selects Spanish, French, or German as the content language for a screenshot scan and the corresponding Tesseract language pack (`spa`, `fra`, or `deu`) is not installed, the application gracefully falls back to English OCR and logs an informational message. The extracted text is still analysed using the appropriate language tier.

---

## 15. Security Considerations

The following security measures are implemented in the current version:

- **Secret key enforcement:** `config.py` uses a `_require_secret_key()` function that raises a `RuntimeError` with a clear message if `SECRET_KEY` is missing or empty. The application cannot start without it.
- **Password hashing:** User passwords are hashed using Werkzeug's `scrypt`-based `generate_password_hash`. Plaintext passwords are never stored.
- **Flask session security:** Session cookies are configured with `HTTPOnly=True` and `SameSite=Lax`. The `SESSION_COOKIE_SECURE` flag is set to `False` by default (suitable for HTTP development). It should be set to `True` in any production deployment served over HTTPS.
- **Debug mode off by default:** `FLASK_DEBUG` defaults to `False`. Debug mode must be explicitly enabled in `.env` for local development.
- **Route access control:** `@login_required` protects all authenticated routes. `@admin_required` protects moderation routes and returns HTTP 401 for unauthenticated requests and HTTP 403 for authenticated non-admin requests.
- **Safe redirect handling:** The `?next=` parameter used after login is validated to reject external URLs and open redirects.
- **Temporary file cleanup:** Uploaded screenshots are deleted immediately after OCR processing, regardless of whether the operation succeeds or fails.
- **Community report moderation:** All submitted reports start in `pending` status and are never immediately visible on the public feed. Only an administrator can approve or reject them.
- **Input validation:** Community report submissions are validated for minimum and maximum lengths, category presence, and a defamation guard. Scan input is validated for empty content and supported scan types.
- **Guest and authenticated scan isolation:** Guest scans store `user_id = NULL`. Authenticated scan details can only be retrieved by the owning user.
- **`.env` excluded from Git:** The `.gitignore` file excludes `.env` files while explicitly allowing `.env.example`.

---

## 16. Current Limitations

The following features are **not** implemented in the current version:

| Limitation | Details |
|------------|---------|
| **Password reset** | There is no "Forgot Password" flow. Users who lose their password cannot recover their account without direct database access. |
| **Per-IP rate limiting** | The community report cooldown is session-based, not IP-based. A user can bypass it by clearing session cookies. |
| **Pagination** | The dashboard shows a maximum of 50 recent scans. The community feed shows a maximum of 50 approved reports. There is no paging control. |
| **User profile page** | There is no settings or profile page. Users cannot change their username, email, or password through the UI. |
| **Scan export** | There is no option to download or export scan history as CSV or PDF. |
| **Non-English ML analysis** | The trained ML model operates on English text only. Spanish, French, and German content is evaluated using heuristic rules, which may miss scam patterns not covered by those rules. |
| **Real-time URL safety lookup** | URL checks are local and structural only. The application does not query any external threat-intelligence database or Google Safe Browsing API. |
| **Multi-language Tesseract** | Only the English Tesseract language model is included by default. Additional language packs must be installed separately. |

---

## 17. Possible Future Improvements

The following enhancements could be considered for future development:

- **Password reset via email:** Add a secure token-based reset flow using Flask-Mail or a similar library.
- **Two-factor authentication (2FA):** Add TOTP-based 2FA for registered users.
- **Per-IP and per-account rate limiting:** Implement server-side request throttling using Flask-Limiter.
- **Pagination:** Add paginated navigation for scan history and community reports.
- **User profile management:** Allow users to update their email and password through a settings page.
- **Scan history export:** Allow users to download their scan history as a CSV file.
- **External URL reputation check:** Integrate an optional lookup against VirusTotal or Google Safe Browsing for URL scans, with the user's consent.
- **Multilingual ML models:** Train or integrate language-specific classifiers for Spanish, French, and German to replace heuristic-only analysis for those languages.
- **Additional languages:** Extend heuristic support to other widely spoken languages such as Hindi, Arabic, or Portuguese.
- **HTTPS and production deployment:** Add instructions and configuration for deploying with a WSGI server (e.g. Gunicorn) behind an Nginx reverse proxy with a TLS certificate.
- **Admin dashboard:** Add a dedicated admin interface for user management, system statistics, and bulk moderation actions.

---

## 18. Academic Project Disclaimer

This project was developed as a final-year B.Sc. Computer Science academic project. It is intended to demonstrate applied knowledge of full-stack web development, machine learning, database design, and software security practices.

**The risk scores and analysis results produced by TrustGuard AI are probabilistic estimates based on algorithmic pattern recognition and heuristic rules. They do not constitute legal, financial, or cybersecurity guarantees of safety or fraud.** The application cannot guarantee that every scam will be detected, and it may produce false positives for legitimate content.

Users are encouraged to:

- Treat results as one input in their decision-making, not as a definitive verdict.
- Verify independently before sharing sensitive personal information or making payments.
- Report genuine scams to the appropriate national authorities or consumer protection agencies.

The ML model is trained on the UCI SMS Spam Collection dataset and is most effective on short English-language messages. Its performance on longer content, non-SMS communication formats, or languages other than English may differ from its performance on the training benchmark.

---

*TrustGuard AI is an open-source academic project. Contributions and feedback are welcome.*
