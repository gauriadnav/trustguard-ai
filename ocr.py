"""
TrustGuard AI — Screenshot OCR Service
Handles image validation, preprocessing, and text extraction using Pillow and pytesseract.
Configures Tesseract executable path via environment variables or standard locations.
"""

import os
import shutil
import logging
from pathlib import Path
from PIL import Image, UnidentifiedImageError
import pytesseract

from config import Config

logger = logging.getLogger("trustguard.ocr")

# Supported file extensions
SUPPORTED_EXTENSIONS = {".png", ".jpg", ".jpeg", ".webp"}

# Standard fallback installation paths for Tesseract on Windows
WINDOWS_SEARCH_PATHS = [
    r"C:\Program Files\Tesseract-OCR\tesseract.exe",
    r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
    os.path.expandvars(r"%LOCALAPPDATA%\Tesseract-OCR\tesseract.exe"),
    os.path.expandvars(r"%LOCALAPPDATA%\Programs\Tesseract-OCR\tesseract.exe"),
]


def resolve_tesseract_cmd():
    """
    Locates the Tesseract executable.
    Priority:
    1. Config.TESSERACT_CMD (from TESSERACT_CMD in .env)
    2. System PATH (shutil.which('tesseract'))
    3. Common Windows installation directories
    """
    # 1. Config override
    if Config.TESSERACT_CMD and Path(Config.TESSERACT_CMD).is_file():
        return str(Path(Config.TESSERACT_CMD))

    # 2. System PATH
    path_which = shutil.which("tesseract")
    if path_which:
        return path_which

    # 3. Known Windows directories
    for candidate in WINDOWS_SEARCH_PATHS:
        if candidate and Path(candidate).is_file():
            return candidate

    return None


# Initialize pytesseract binary path at module load time if resolved
_initial_tess_cmd = resolve_tesseract_cmd()
if _initial_tess_cmd:
    pytesseract.pytesseract.tesseract_cmd = _initial_tess_cmd


def is_tesseract_available():
    """
    Check if Tesseract OCR is installed and accessible.
    Returns (available: bool, path_or_message: str).
    """
    tess_path = resolve_tesseract_cmd()
    if tess_path:
        pytesseract.pytesseract.tesseract_cmd = tess_path
        return True, tess_path
    return False, (
        "Tesseract OCR executable is not installed or could not be found. "
        "Please install Tesseract OCR and set TESSERACT_CMD in your .env file."
    )



def validate_image_file(file_path):
    """
    Validate that the file exists, has a permitted extension,
    and is a valid, readable image using Pillow.
    Returns (is_valid: bool, error_message: str).
    """
    path = Path(file_path)

    # 1. Check existence
    if not path.is_file():
        return False, "Uploaded file not found on server."

    # 2. Check extension
    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        return False, f"Unsupported file extension '{ext}'. Permitted formats: PNG, JPG, JPEG, WEBP."

    # 3. Check file size (5MB limit)
    size = path.stat().st_size
    if size == 0:
        return False, "Uploaded file is empty (0 bytes)."
    if size > Config.MAX_CONTENT_LENGTH:
        return False, f"File size ({size / (1024*1024):.1f}MB) exceeds the 5MB maximum limit."

    # 4. Verify actual image content with Pillow
    try:
        with Image.open(path) as img:
            img.verify()  # Verifies image header and integrity
        # Re-open to confirm loadable (verify() invalidates file pointer in some PIL versions)
        with Image.open(path) as img:
            img.load()
        return True, "Valid image."
    except (UnidentifiedImageError, OSError, SyntaxError) as e:
        logger.warning(f"Invalid image file {file_path}: {e}")
        return False, "The uploaded file is corrupted or not a valid image format."


def get_installed_ocr_languages():
    """
    Query the Tesseract OCR engine for installed language datasets.
    Returns a list of available language codes (e.g. ['eng', 'osd']).
    """
    available, _ = is_tesseract_available()
    if not available:
        return []
    try:
        langs = pytesseract.get_languages(config="")
        return langs if isinstance(langs, list) else ["eng"]
    except Exception as e:
        logger.warning(f"Failed to query Tesseract languages: {e}")
        return ["eng"]


# Mapping from ISO 639-1 language codes to standard Tesseract traineddata identifiers
OCR_LANG_MAP = {
    "en": "eng",
    "es": "spa",
    "fr": "fra",
    "de": "deu",
    "auto": "eng"
}


def extract_text_from_image(image_path, lang=None):
    """
    Extract readable text from a verified image file.
    
    Parameters:
        image_path: Path to the image file.
        lang (str, optional): Target language code ('en', 'es', 'fr', 'de', or Tesseract code).
                              If the requested language model is not installed locally,
                              gracefully falls back to 'eng' (standard Latin alphabet model).
    
    Returns:
        dict: {
            "success": bool,
            "text": str,
            "error": str or None,
            "char_count": int,
            "ocr_lang": str
        }
    """
    # Verify Tesseract binary presence
    available, msg_or_path = is_tesseract_available()
    if not available:
        logger.warning(f"Tesseract OCR unavailable: {msg_or_path}")
        return {
            "success": False,
            "text": "",
            "error": msg_or_path,
            "char_count": 0,
            "ocr_lang": "none"
        }

    # Validate image integrity
    is_valid, validation_msg = validate_image_file(image_path)
    if not is_valid:
        return {
            "success": False,
            "text": "",
            "error": validation_msg,
            "char_count": 0,
            "ocr_lang": "none"
        }

    # Determine Tesseract language with graceful fallback
    installed_langs = get_installed_ocr_languages()
    target_tess_lang = "eng"
    if lang:
        requested_code = OCR_LANG_MAP.get(lang.lower(), lang.lower())
        if requested_code in installed_langs:
            target_tess_lang = requested_code
        else:
            logger.info(
                f"Requested OCR language '{lang}' ({requested_code}) is not installed in local tessdata "
                f"(available: {installed_langs}). Gracefully falling back to 'eng'."
            )
            target_tess_lang = "eng"

    try:
        # Load image via Pillow
        with Image.open(image_path) as img:
            # Convert RGBA / P images to RGB for clean OCR
            if img.mode in ("RGBA", "P", "LA"):
                img = img.convert("RGB")

            # Perform OCR text extraction with selected/fallback language
            extracted = pytesseract.image_to_string(img, lang=target_tess_lang)

        cleaned_text = (extracted or "").strip()

        if not cleaned_text:
            return {
                "success": False,
                "text": "",
                "error": (
                    "No readable text could be detected in this screenshot. "
                    "Please ensure the image contains clear, legible text or try uploading a higher-resolution image."
                ),
                "char_count": 0,
                "ocr_lang": target_tess_lang
            }

        return {
            "success": True,
            "text": cleaned_text,
            "error": None,
            "char_count": len(cleaned_text),
            "ocr_lang": target_tess_lang
        }

    except pytesseract.TesseractNotFoundError:
        return {
            "success": False,
            "text": "",
            "error": (
                "Tesseract OCR executable was not found. "
                "Please verify that Tesseract is installed and TESSERACT_CMD is configured in .env."
            ),
            "char_count": 0,
            "ocr_lang": target_tess_lang
        }
    except pytesseract.TesseractError as te:
        logger.warning(f"Tesseract OCR engine error with lang '{target_tess_lang}': {te}")
        # If execution with specialized language failed, retry with 'eng'
        if target_tess_lang != "eng" and "eng" in installed_langs:
            try:
                with Image.open(image_path) as img:
                    if img.mode in ("RGBA", "P", "LA"):
                        img = img.convert("RGB")
                    retry_text = (pytesseract.image_to_string(img, lang="eng") or "").strip()
                if retry_text:
                    return {
                        "success": True,
                        "text": retry_text,
                        "error": None,
                        "char_count": len(retry_text),
                        "ocr_lang": "eng"
                    }
            except Exception:
                pass
        return {
            "success": False,
            "text": "",
            "error": "The OCR engine could not process this image with the requested language data.",
            "char_count": 0,
            "ocr_lang": target_tess_lang
        }
    except Exception as e:
        logger.error(f"OCR extraction exception: {e}", exc_info=True)
        return {
            "success": False,
            "text": "",
            "error": "An unexpected error occurred while processing the screenshot image.",
            "char_count": 0,
            "ocr_lang": target_tess_lang
        }
