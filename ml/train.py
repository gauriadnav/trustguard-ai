"""
ML Model Training and Evaluation Pipeline for TrustGuard AI
Trains a TF-IDF + Logistic Regression text classifier on the verified dataset,
evaluates on a held-out test set, and exports model and vectorizer artifacts.
"""

import sys
from pathlib import Path
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
import joblib

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
ML_DIR = BASE_DIR / "ml"
DATASET_PATH = ML_DIR / "dataset.csv"
MODEL_PATH = ML_DIR / "model.pkl"
VECTORIZER_PATH = ML_DIR / "vectorizer.pkl"


def train_and_evaluate():
    print("=" * 60)
    print(" TrustGuard AI — Machine Learning Model Training")
    print("=" * 60)

    # 1. Load Dataset
    if not DATASET_PATH.exists():
        print(f"[-] Error: Dataset not found at {DATASET_PATH}")
        print("    Please run ml/download_dataset.py first.")
        sys.exit(1)

    print(f"[*] Loading dataset from: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)
    print(f"[+] Loaded {len(df)} records.")
    print(f"[+] Class distribution:\n{df['label_text'].value_counts().to_string()}\n")

    # 2. Text Preprocessing & Splitting
    X = df["text"].astype(str)
    y = df["label"].astype(int)

    # 80% Training, 20% Held-out Test partition (stratified to preserve class ratio)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[*] Training samples: {len(X_train)} | Test samples: {len(X_test)}")

    # 3. TF-IDF Feature Extraction
    print("[*] Fitting TfidfVectorizer (unigrams + bigrams, sublinear_tf=True)...")
    vectorizer = TfidfVectorizer(
        max_features=5000,
        ngram_range=(1, 2),
        stop_words="english",
        sublinear_tf=True,
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    print(f"[+] Vectorizer vocabulary size: {len(vectorizer.vocabulary_)} features")

    # 4. Model Training & Selection
    # We evaluate Logistic Regression (calibrated probabilities) and MultinomialNB
    print("\n[*] Training Classifiers on Training Set...")

    models = {
        "Multinomial Naive Bayes": MultinomialNB(alpha=0.1),
        "Logistic Regression": LogisticRegression(C=1.0, max_iter=1000, random_state=42),
    }

    best_model = None
    best_f1 = -1.0
    best_name = ""

    for name, clf in models.items():
        clf.fit(X_train_vec, y_train)
        preds = clf.predict(X_test_vec)
        f1 = f1_score(y_test, preds)
        acc = accuracy_score(y_test, preds)
        prec = precision_score(y_test, preds)
        rec = recall_score(y_test, preds)
        print(f"\n--- {name} Performance on 20% Held-Out Test Set ---")
        print(f"  Accuracy  : {acc:.4f} ({acc * 100:.2f}%)")
        print(f"  Precision : {prec:.4f} ({prec * 100:.2f}%)")
        print(f"  Recall    : {rec:.4f} ({rec * 100:.2f}%)")
        print(f"  F1-Score  : {f1:.4f}")

        if f1 > best_f1:
            best_f1 = f1
            best_model = clf
            best_name = name

    print(f"\n[+] Selected Best Classifier: {best_name} (F1: {best_f1:.4f})")

    # 5. Detailed Evaluation of Selected Model
    y_pred = best_model.predict(X_test_vec)
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()

    print("\n" + "=" * 60)
    print(f" Final Evaluation Metrics ({best_name}) on Held-Out Test Set")
    print("=" * 60)
    print(f"True Negatives (Legitimate correctly identified) : {tn}")
    print(f"False Positives (Legitimate flagged as scam)     : {fp}")
    print(f"False Negatives (Scams missed)                   : {fn}")
    print(f"True Positives (Scams correctly caught)          : {tp}")
    print("\nDetailed Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["Legitimate (Ham)", "Scam (Spam)"]))

    # 6. Save Model and Vectorizer Artifacts
    print("[*] Serializing trained artifacts...")
    joblib.dump(best_model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)
    print(f"[+] Saved model to      : {MODEL_PATH}")
    print(f"[+] Saved vectorizer to : {VECTORIZER_PATH}")

    # 7. Verification Test with Real Scenarios
    print("\n" + "=" * 60)
    print(" Sanity Check: Predictions on Unseen Test Scenarios")
    print("=" * 60)
    test_samples = [
        "Hey, are we still meeting for lunch tomorrow at 12:30?",
        "URGENT: Your bank account is locked! Click here to verify your credentials immediately or access will be revoked.",
        "Congratulations! You won a $1000 Walmart Gift Card. Call now to claim your prize.",
        "Hi Mom, I lost my phone, please text me on this new WhatsApp number and send money for rent."
    ]

    for sample in test_samples:
        sample_vec = vectorizer.transform([sample])
        # Probability of scam (class 1)
        prob = best_model.predict_proba(sample_vec)[0][1]
        label = "SCAM" if prob >= 0.5 else "LEGITIMATE"
        print(f"\nText: \"{sample[:70]}...\"")
        print(f" -> Predicted: {label} (Scam Probability: {prob:.4f} / {prob * 100:.1f}%)")

    print("\n[+] Training and evaluation completed successfully.")


if __name__ == "__main__":
    train_and_evaluate()
