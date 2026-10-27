"""
Dataset Downloader and Verifier for TrustGuard AI
Downloads the official UCI SMS Spam Collection dataset, verifies its contents,
and prepares a clean CSV file at ml/dataset.csv.
"""

import os
import zipfile
import io
import urllib.request
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ML_DIR = BASE_DIR / "ml"
OUTPUT_CSV = ML_DIR / "dataset.csv"

# Primary UCI Machine Learning Repository URL
UCI_ZIP_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
# Fallback raw mirror (same canonical file from UC Irvine DAT8 repository)
FALLBACK_TSV_URL = "https://raw.githubusercontent.com/justmarkham/DAT8/master/data/sms.tsv"


def fetch_dataset():
    os.makedirs(ML_DIR, exist_ok=True)

    print(f"[*] Attempting download from official UCI repository:\n    {UCI_ZIP_URL}")
    raw_content = None
    
    headers = {"User-Agent": "TrustGuard-AI-Academic-Project/1.0"}
    req = urllib.request.Request(UCI_ZIP_URL, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            zip_bytes = response.read()
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
                # The file inside the zip is named 'SMSSpamCollection'
                file_names = z.namelist()
                print(f"[+] Zip contents: {file_names}")
                target_file = next((name for name in file_names if "SMSSpamCollection" in name and not name.endswith("/")), None)
                if target_file:
                    raw_content = z.read(target_file).decode("utf-8", errors="replace")
                    print(f"[+] Successfully extracted '{target_file}' ({len(raw_content)} bytes).")
    except Exception as e:
        print(f"[-] UCI zip download encountered an issue: {e}")
        print(f"[*] Trying verified raw fallback mirror:\n    {FALLBACK_TSV_URL}")
        req_fallback = urllib.request.Request(FALLBACK_TSV_URL, headers=headers)
        with urllib.request.urlopen(req_fallback, timeout=30) as resp:
            raw_content = resp.read().decode("utf-8", errors="replace")
            print(f"[+] Successfully downloaded raw dataset ({len(raw_content)} bytes).")

    if not raw_content:
        raise RuntimeError("Failed to obtain dataset from both UCI and fallback mirrors.")

    # Parse tab-separated values
    lines = [line.strip() for line in raw_content.splitlines() if line.strip()]
    records = []
    skipped = 0

    for line in lines:
        parts = line.split("\t", 1)
        if len(parts) == 2:
            label, text = parts[0].strip().lower(), parts[1].strip()
            # Standardize: 1 for spam/scam, 0 for ham/legitimate
            if label in ("ham", "spam"):
                binary_label = 1 if label == "spam" else 0
                records.append({"label": binary_label, "label_text": label, "text": text})
            else:
                skipped += 1
        else:
            skipped += 1

    df = pd.DataFrame(records)
    print(f"[+] Total records parsed: {len(df)} (Skipped invalid lines: {skipped})")

    # Verification checks
    label_counts = df["label_text"].value_counts().to_dict()
    print(f"[+] Label distribution: {label_counts}")
    assert "ham" in label_counts and "spam" in label_counts, "Dataset must contain both ham and spam!"
    assert len(df) >= 5000, f"Expected >5000 records, found {len(df)}"

    # Save to clean CSV
    df[["label", "label_text", "text"]].to_csv(OUTPUT_CSV, index=False, encoding="utf-8")
    print(f"[+] Successfully verified and saved dataset to:\n    {OUTPUT_CSV}")
    print("\n--- First 5 Records Sample ---")
    for idx, row in df.head(5).iterrows():
        print(f"[{row['label_text'].upper()}] {row['text'][:80]}...")

    return df


if __name__ == "__main__":
    fetch_dataset()
