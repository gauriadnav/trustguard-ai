import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the project
BASE_DIR = Path(__file__).resolve().parent

# Load environment variables from .env file
load_dotenv(BASE_DIR / ".env")


def _require_secret_key() -> str:
    """
    Read SECRET_KEY from the environment and fail fast with a descriptive
    message if it is missing or empty.

    For local development, set SECRET_KEY in your .env file.
    For production, set it as an OS / container environment variable.
    Never hard-code a fallback value in source code.
    """
    key = os.getenv("SECRET_KEY", "").strip()
    if not key:
        raise RuntimeError(
            "[TrustGuard AI] SECRET_KEY is not set. "
            "Add SECRET_KEY=<your-secret> to your .env file for local development, "
            "or set it as an environment variable in your production deployment. "
            "The application cannot start without a configured secret key."
        )
    return key


class Config:
    """Application configuration loaded from environment variables."""

    # Flask Core
    # SECRET_KEY is required — the application refuses to start if it is absent.
    # Set it in .env (local dev) or as an OS/container env var (production).
    SECRET_KEY = _require_secret_key()
    # Debug mode defaults to False (production-safe).
    # Set FLASK_DEBUG=True in your .env file to enable debug mode locally.
    DEBUG = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "t")

    # MySQL Database Settings
    DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
    DB_PORT = int(os.getenv("DB_PORT", "3306"))
    DB_USER = os.getenv("DB_USER", "root")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_NAME = os.getenv("DB_NAME", "trustguard_db")

    # File Uploads
    UPLOAD_FOLDER = BASE_DIR / os.getenv("UPLOAD_FOLDER", "uploads")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(5 * 1024 * 1024)))  # 5MB default
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}

    # OCR Settings
    TESSERACT_CMD = os.getenv("TESSERACT_CMD", "")

    # ML Model Artifacts Paths
    MODEL_PATH = BASE_DIR / "ml" / "model.pkl"
    VECTORIZER_PATH = BASE_DIR / "ml" / "vectorizer.pkl"
    DATASET_PATH = BASE_DIR / "ml" / "dataset.csv"


# Ensure upload folder exists
os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
