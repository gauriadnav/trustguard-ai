"""
TrustGuard AI — Scam Detection & Risk Scoring Engine
Combines Machine Learning inference (TF-IDF + Naive Bayes),
Rule-Based Heuristic Warning Indicators, and Local URL Pattern Checks.
"""

import re
import urllib.parse
from pathlib import Path
import joblib

from config import Config

# Load trained ML model and vectorizer
_model = None
_vectorizer = None


def _get_ml_artifacts():
    """Lazy-load and cache the serialized ML model and vectorizer."""
    global _model, _vectorizer
    if _model is None or _vectorizer is None:
        if Config.MODEL_PATH.exists() and Config.VECTORIZER_PATH.exists():
            _model = joblib.load(Config.MODEL_PATH)
            _vectorizer = joblib.load(Config.VECTORIZER_PATH)
        else:
            raise FileNotFoundError(
                f"Model artifacts missing. Expected {Config.MODEL_PATH} and {Config.VECTORIZER_PATH}."
            )
    return _model, _vectorizer


# High-risk TLDs commonly abused in phishing/spam campaigns
HIGH_RISK_TLDS = {
    "tk", "xyz", "top", "click", "buzz", "work", "cf", "gq", "ml", "country", "stream"
}

# Known URL shortener services
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl", "cutt.ly"
}

# Targeted brand keywords often spoofed in phishing subdomains
TARGET_BRANDS = [
    "paypal", "apple", "google", "microsoft", "netflix", "amazon",
    "chase", "bankofamerica", "wellsfargo", "binance", "coinbase"
]

# Heuristic Warning Rules with severity weights and explanations
HEURISTIC_RULES = [
    # 1. Urgency & Coercion
    {
        "pattern": r"(?i)\b(urgent|immediately|within 24 hours|account suspended|final notice|immediate action|act now|time sensitive)\b",
        "weight": 18,
        "flag": "High Urgency / Coercive Deadline",
        "description": "Uses pressure tactics or artificial deadlines to prompt hasty user decisions."
    },
    # 2. Financial & Payment Demands
    {
        "pattern": r"(?i)\b(gift card|wire transfer|western union|crypto|bitcoin|usdt|cash app|itunes card|steam card)\b",
        "weight": 22,
        "flag": "Untraceable Payment Method Requested",
        "description": "Requests payment through non-reversible or difficult-to-trace channels."
    },
    # 3. Credential & Security Requests
    {
        "pattern": r"(?i)\b(enter your password|verify your pin|send your otp|confirm your credentials|social security|ssn|banking login)\b",
        "weight": 25,
        "flag": "Sensitive Credential / OTP Request",
        "description": "Demands sensitive security credentials, OTPs, or identity numbers."
    },
    # 4. Job / Internship Scams
    {
        "pattern": r"(?i)\b(earn \$\d+[\/\s]*day|work from home 2 hours|no experience required guaranteed|registration fee|equipment fee|training fee required)\b",
        "weight": 20,
        "flag": "Suspicious Job / Internship Offer Pattern",
        "description": "Exhibits hallmarks of employment scams (unrealistic compensation or upfront fee requirements)."
    },
    # 5. Prize & Lottery Claims
    {
        "pattern": r"(?i)\b(you have won|lottery winner|selected to receive|claim your prize|congratulations you won)\b",
        "weight": 18,
        "flag": "Unsolicited Prize / Lottery Claim",
        "description": "Promises unsolicited financial rewards or sweepstakes payouts."
    },
    # 6. Impersonation of Authority / Support
    {
        "pattern": r"(?i)\b(fraud prevention department|customer support team|irs audit|customs officer|security team)\b",
        "weight": 14,
        "flag": "Authority / Support Impersonation",
        "description": "Adopts corporate or regulatory authority phrasing to establish false credibility."
    }
]

# Supported language definitions and localized threat rules
SUPPORTED_LANGUAGES = {
    "auto": "Auto-Detect Language",
    "en": "English",
    "es": "Spanish (Español)",
    "fr": "French (Français)",
    "de": "German (Deutsch)",
    "other": "Other / Unsupported"
}

MULTILINGUAL_HEURISTIC_RULES = {
    "en": HEURISTIC_RULES,
    "es": [
        {
            "pattern": r"(?i)\b(urgente|inmediatamente|cuenta suspendida|último aviso|ultimo aviso|actúa ahora|actue ahora|dentro de 24 horas|tiempo limitado)\b",
            "weight": 18,
            "flag": "Alta Urgencia / Plazo Coactivo (High Urgency)",
            "description": "Utiliza tácticas de presión o plazos artificiales para forzar decisiones apresuradas."
        },
        {
            "pattern": r"(?i)\b(tarjeta de regalo|transferencia bancaria|western union|cripto|bitcoin|usdt|tarjeta steam|tarjeta itunes)\b",
            "weight": 22,
            "flag": "Método de Pago No Rastreable (Untraceable Payment)",
            "description": "Solicita pagos a través de canales no reversibles o difíciles de rastrear."
        },
        {
            "pattern": r"(?i)\b(ingrese su contraseña|ingrese su clave|verifique su pin|código otp|codigo otp|confirme sus credenciales|banca en línea|datos de acceso)\b",
            "weight": 25,
            "flag": "Solicitud de Credenciales / OTP (Credential Request)",
            "description": "Exige credenciales de seguridad sensibles, códigos OTP o contraseñas bancarias."
        },
        {
            "pattern": r"(?i)\b(gane \$\d+[\/\s]*día|gane \$\d+[\/\s]*dia|trabajo desde casa|sin experiencia|tarifa de registro|tarifa de capacitación|pago por adelantado)\b",
            "weight": 20,
            "flag": "Patrón de Estafa Laboral (Job / Internship Scam)",
            "description": "Presenta indicios de fraude de empleo (ingresos poco realistas o pago previo exigido)."
        },
        {
            "pattern": r"(?i)\b(ha ganado|ganador de la lotería|ganador de la loteria|seleccionado para recibir|reclame su premio|felicidades por ganar)\b",
            "weight": 18,
            "flag": "Premio o Lotería No Solicitada (Unsolicited Prize Claim)",
            "description": "Promete premios monetarios no solicitados o recompensas fraudulentas."
        },
        {
            "pattern": r"(?i)\b(departamento de fraudes|soporte técnico|soporte tecnico|equipo de seguridad|servicio al cliente oficial)\b",
            "weight": 14,
            "flag": "Suplantación de Autoridad o Soporte (Authority Impersonation)",
            "description": "Adopta terminología corporativa o regulatoria para establecer credibilidad fingida."
        }
    ],
    "fr": [
        {
            "pattern": r"(?i)\b(urgent|immédiatement|immediatement|compte suspendu|dernier avis|dans les 24 heures|action immédiate|action requise)\b",
            "weight": 18,
            "flag": "Urgence Élevée / Pression Temporelle (High Urgency)",
            "description": "Utilise des tactiques de pression ou des délais artificiels pour forcer une décision rapide."
        },
        {
            "pattern": r"(?i)\b(carte cadeau|virement bancaire|western union|crypto|bitcoin|usdt|carte steam|carte itunes)\b",
            "weight": 22,
            "flag": "Méthode de Paiement Non Traçable (Untraceable Payment)",
            "description": "Exige des paiements via des canaux non réversibles ou difficilement traçables."
        },
        {
            "pattern": r"(?i)\b(entrez votre mot de passe|vérifiez votre pin|verifiez votre pin|code otp|confirmez vos identifiants|accès bancaire)\b",
            "weight": 25,
            "flag": "Demande d'Identifiants Sensibles / OTP (Credential Request)",
            "description": "Exige la saisie de mots de passe, codes de sécurité ou accès bancaires."
        },
        {
            "pattern": r"(?i)\b(gagnez \$\d+|travail à domicile|travail a domicile|sans expérience|frais d'inscription|frais de formation)\b",
            "weight": 20,
            "flag": "Modèle d'Escroquerie à l'Emploi (Job Offer Scam)",
            "description": "Présente des signes typiques d'arnaque au recrutement (rémunération irréaliste ou frais initiaux)."
        },
        {
            "pattern": r"(?i)\b(vous avez gagné|vous avez gagne|gagnant de la loterie|réclamez votre prix|reclamez votre prix|félicitations)\b",
            "weight": 18,
            "flag": "Gain Non Sollicité / Loterie (Prize Claim)",
            "description": "Promet des gains financiers ou récompenses inattendus."
        },
        {
            "pattern": r"(?i)\b(service anti-fraude|service client|support technique|équipe de sécurité|banque centrale)\b",
            "weight": 14,
            "flag": "Usurpation d'Autorité ou de Support (Authority Impersonation)",
            "description": "Emprunte le langage institutionnel pour inspirer une fausse confiance."
        }
    ],
    "de": [
        {
            "pattern": r"(?i)\b(dringend|sofort|konto gesperrt|gesperrt|letzte mahnung|innerhalb von 24 stunden|sofortige maßnahme|sofortige massnahme|sofort handeln)\b",
            "weight": 18,
            "flag": "Hohe Dringlichkeit / Fristdruck (High Urgency)",
            "description": "Nutzt künstlichen Zeitdruck, um unüberlegte Aktionen zu erzwingen."
        },
        {
            "pattern": r"(?i)\b(geschenkkarte|banküberweisung|bankueberweisung|western union|krypto|bitcoin|usdt|steam-karte|itunes-karte)\b",
            "weight": 22,
            "flag": "Nicht Rückverfolgbare Zahlungsmethode (Untraceable Payment)",
            "description": "Fordert Zahlungen über irreversible oder anonyme Transaktionskanäle."
        },
        {
            "pattern": r"(?i)\b(passwort(?:\s+\w+)?\s+eingeben|passwort eingeben|pin bestätigen|otp-code|anmeldedaten|zugangsdaten|online-banking zugang)\b",
            "weight": 25,
            "flag": "Abfrage Sensibler Zugangsdaten / OTP (Credential Request)",
            "description": "Verlangt die Eingabe von Passwörtern, PINs oder Sicherheits-Tokens."
        },
        {
            "pattern": r"(?i)\b(verdienen sie \$\d+|heimarbeit|keine erfahrung nötig|registrierungsgebühr|schulungsgebühr)\b",
            "weight": 20,
            "flag": "Verdächtiges Stellenangebot (Job Scam)",
            "description": "Zeigt Merkmale von Rekrutierungsbetrug (unrealistisches Gehalt oder Vorabgebühren)."
        },
        {
            "pattern": r"(?i)\b(sie haben gewonnen|lotteriegewinner|gewinn anfordern|herzlichen glückwunsch)\b",
            "weight": 18,
            "flag": "Unaufgeforderter Gewinn / Lotterie (Unsolicited Prize Claim)",
            "description": "Verspricht unaufgeforderte Geldpreise oder Lotteriegewinne."
        },
        {
            "pattern": r"(?i)\b(betrugsabteilung|kundensupport|sicherheitsteam|sicherheitsabteilung)\b",
            "weight": 14,
            "flag": "Behörden- oder Support-Täuschung (Authority Impersonation)",
            "description": "Gibt vor, eine offizielle Sicherheits- oder Bankenabteilung zu sein."
        }
    ]
}


def detect_language(text):
    """
    Detect the most probable language among supported languages ('en', 'es', 'fr', 'de').
    Uses characteristic word tokens and accent frequencies.
    Returns language code ('en', 'es', 'fr', 'de', or 'other').
    """
    if not text or not text.strip():
        return "en"

    text_lower = text.lower()

    # Special character markers
    es_chars = sum(text_lower.count(c) for c in ("ñ", "¿", "¡", "á", "í", "ó", "ú"))
    fr_chars = sum(text_lower.count(c) for c in ("é", "è", "ê", "à", "ç", "œ", "ù", "û", "î"))
    de_chars = sum(text_lower.count(c) for c in ("ä", "ö", "ü", "ß"))

    # Word markers (using word boundary matching)
    words = set(re.findall(r"\b[a-zA-Záéíóúñèêàçœùûîäöüß]+\b", text_lower))

    es_words = len(words.intersection({"el", "la", "de", "en", "y", "que", "por", "con", "para", "cuenta", "tarjeta", "urgente", "ganar", "banco", "su"}))
    fr_words = len(words.intersection({"le", "la", "de", "et", "en", "du", "que", "pour", "avec", "compte", "carte", "urgent", "votre", "banque"}))
    de_words = len(words.intersection({"der", "die", "das", "und", "in", "zu", "den", "von", "mit", "für", "konto", "passwort", "dringend", "ihr", "bank"}))
    en_words = len(words.intersection({"the", "and", "is", "to", "of", "for", "you", "your", "account", "password", "urgent", "bank", "please", "with"}))

    scores = {
        "es": es_words * 2 + es_chars * 3,
        "fr": fr_words * 2 + fr_chars * 3,
        "de": de_words * 2 + de_chars * 3,
        "en": en_words * 2
    }

    # If no markers found at all and non-latin scripts (like Cyrillic, Arabic, Chinese, Devanagari) are dominant:
    non_latin = len(re.findall(r"[^\x00-\x7F\u00C0-\u00FF]", text))
    if non_latin > len(text) * 0.4 and sum(scores.values()) == 0:
        return "other"

    best_lang, best_score = max(scores.items(), key=lambda item: item[1])
    if best_score > 0:
        return best_lang

    # Default to English if ambiguous
    return "en"



def extract_urls(text):
    """Find all http/https/www URLs in text."""
    url_pattern = r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)"
    return re.findall(url_pattern, text)


def analyze_url_patterns(url_string):
    """
    Perform local, deterministic syntactic analysis on a URL.
    Does NOT require external network calls or third-party APIs.
    """
    findings = []
    penalty = 0

    if not url_string.startswith(("http://", "https://")):
        url_string = "http://" + url_string

    try:
        parsed = urllib.parse.urlparse(url_string)
        hostname = (parsed.hostname or "").lower()
    except Exception:
        return 20, [{"flag": "Malformed URL", "description": "URL syntax is invalid or obfuscated."}]

    # 1. Unencrypted HTTP
    if parsed.scheme == "http":
        penalty += 10
        findings.append({
            "flag": "Unencrypted HTTP Protocol",
            "description": "Transmission lacks SSL/TLS encryption, leaving data vulnerable in transit."
        })

    # 2. Raw IP address instead of domain name
    ip_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ip_pattern, hostname):
        penalty += 30
        findings.append({
            "flag": "Bare IP Address in Hostname",
            "description": "Direct numerical IP address used instead of a registered domain, a common phishing pattern."
        })

    # 3. Userinfo '@' symbol trick
    if "@" in parsed.netloc:
        penalty += 25
        findings.append({
            "flag": "Obfuscated Userinfo (@) in URL",
            "description": "Contains '@' symbol in authority section, commonly used to disguise destination domain."
        })

    # 4. Abused or suspicious TLD
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in HIGH_RISK_TLDS:
        penalty += 18
        findings.append({
            "flag": f"High-Risk Top-Level Domain (.{tld})",
            "description": f"Domain utilizes the '.{tld}' TLD, frequently observed in disposable scam domains."
        })

    # 5. URL Shortener Service
    if hostname in SHORTENER_DOMAINS:
        penalty += 12
        findings.append({
            "flag": "URL Shortening Service Detected",
            "description": "Link destination is masked behind a shortening proxy, hiding the real target."
        })

    # 6. Brand Spoofing in Subdomains (e.g. paypal.com.attacker.com)
    for brand in TARGET_BRANDS:
        if brand in hostname:
            # Check if brand is not the apex registered domain
            parts = hostname.split(".")
            if len(parts) > 2 and brand not in parts[-2]:
                penalty += 25
                findings.append({
                    "flag": f"Suspected Brand Impersonation ({brand.title()})",
                    "description": f"Legitimate brand name '{brand.title()}' appears in a subdomain rather than the root domain."
                })
                break

    # 7. Excessive Subdomains (Domain depth > 3)
    if len(hostname.split(".")) > 4:
        penalty += 10
        findings.append({
            "flag": "Excessive Subdomain Depth",
            "description": "Multiple subdomain levels used, frequently correlated with phishing infrastructure."
        })

    return penalty, findings


def generate_recommendations(risk_level, detected_flags):
    """Generate clear, practical defensive advice based on findings."""
    recs = []

    if risk_level == "High Risk":
        recs.append("Do not click links, download attachments, or call phone numbers provided in this message.")
        recs.append("Do not send money, gift cards, or cryptocurrency under any circumstances.")
        recs.append("Never share one-time passwords (OTPs), PINs, or account passwords.")
        recs.append("If this claims to be from an organization you use, contact them via their official website or verified app.")
    elif risk_level == "Suspicious":
        recs.append("Exercise elevated caution. Verify the sender's identity through an independent channel before replying.")
        recs.append("Inspect the exact sender email address or web address for subtle spelling variations.")
        recs.append("Be wary of urgent demands or requests that bypass standard organizational workflows.")
    else:
        recs.append("No prominent scam patterns detected, but standard digital security practices still apply.")
        recs.append("Always verify unexpected payment requests, even from known contacts whose accounts might be compromised.")

    return recs


def analyze_content(content, scan_type="text", language="auto"):
    """
    Main Analysis Entry Point for TrustGuard AI.
    
    Parameters:
        content (str): The raw text message, email body, URL, or extracted OCR text.
        scan_type (str): 'text', 'email', 'url', 'screenshot', or 'job_offer'.
        language (str): 'auto', 'en', 'es', 'fr', 'de', or 'other'.
        
    Returns:
        dict: Standardized analysis report containing risk score, category, flags,
              safety advice, language metadata, and uncertainty disclaimer.
    """
    content_clean = (content or "").strip()
    if not content_clean:
        return {
            "scan_type": scan_type,
            "input_snippet": "",
            "risk_score": 0,
            "risk_level": "Low Risk",
            "confidence_score": 0.0,
            "ml_probability": 0.0,
            "ml_applied": False,
            "detected_flags": [],
            "recommendations": ["No content provided for analysis."],
            "language_info": {
                "code": "en",
                "name": "English",
                "tier": "Tier 1 — Full ML & Heuristics",
                "ml_applied": False,
                "mode": "None",
                "note": "No content provided."
            },
            "disclaimer": _DISCLAIMER,
        }

    # 1. Resolve language
    if not language or language == "auto":
        resolved_lang = detect_language(content_clean)
    elif language in ("en", "es", "fr", "de", "other"):
        resolved_lang = language
    else:
        resolved_lang = "en"

    lang_display_names = {
        "en": "English",
        "es": "Spanish (Español)",
        "fr": "French (Français)",
        "de": "German (Deutsch)",
        "other": "Other / Unsupported"
    }
    lang_name = lang_display_names.get(resolved_lang, "English")

    detected_flags: list[dict[str, str]] = []
    heuristic_penalty = 0
    ml_prob = None
    ml_score = 0.0

    # 2. Heuristic Pattern Checks based on resolved language
    if resolved_lang in MULTILINGUAL_HEURISTIC_RULES:
        rules_to_run: list[dict[str, str | int]] = MULTILINGUAL_HEURISTIC_RULES[resolved_lang]
        for rule in rules_to_run:
            if re.search(str(rule["pattern"]), content_clean):
                heuristic_penalty += int(rule["weight"])
                detected_flags.append({
                    "category": f"Heuristic Indicator ({lang_name.split()[0]})",
                    "flag": str(rule["flag"]),
                    "description": str(rule["description"])
                })

    # 3. URL Pattern Checks (Universal across all languages)
    urls_found = []
    if scan_type == "url":
        urls_found = [content_clean]
    else:
        urls_found = extract_urls(content_clean)

    url_penalty_total = 0
    for u in urls_found[:3]:  # Analyze up to first 3 URLs
        u_penalty, u_findings = analyze_url_patterns(u)
        url_penalty_total += u_penalty
        for item in u_findings:
            detected_flags.append({
                "category": "URL Pattern",
                "flag": f"[{u[:30]}...] {item['flag']}",
                "description": item["description"]
            })

    combined_penalties = heuristic_penalty + url_penalty_total

    # 4. Machine Learning Inference & Tier Routing
    if resolved_lang == "en":
        # Tier 1: Full Hybrid ML + English Heuristics + URL Forensics
        model, vectorizer = _get_ml_artifacts()
        sample_vec = vectorizer.transform([content_clean])
        probs = model.predict_proba(sample_vec)[0]
        ml_prob = float(probs[1])
        ml_score = ml_prob * 100.0

        # Formula: 45% ML + 55% Heuristic & URL signals
        composite_score = round((0.45 * ml_score) + (0.55 * min(combined_penalties * 1.5, 100)))
        confidence = float(round(abs(ml_prob - 0.5) * 2 * 0.5 + 0.5, 2))

        language_info = {
            "code": "en",
            "name": "English",
            "tier": "Tier 1 — Full ML & Heuristics",
            "ml_applied": True,
            "mode": "Full Hybrid (ML + Heuristics + URL Forensics)",
            "note": "Complete threat evaluation using English TF-IDF classifier, heuristic urgency indicators, and local URL forensics."
        }
    elif resolved_lang in ("es", "fr", "de"):
        # Tier 2: Localized Heuristics + URL Forensics (English ML explicitly bypassed)
        ml_prob = None
        composite_score = min(round(combined_penalties * 1.5), 100)
        confidence = 0.82 if combined_penalties > 0 else 0.70

        language_info = {
            "code": resolved_lang,
            "name": lang_name,
            "tier": f"Tier 2 — Localized {lang_name.split()[0]} Heuristics & URL Forensics",
            "ml_applied": False,
            "mode": "Multilingual Heuristics + URL Forensics",
            "note": f"Evaluated using localized {lang_name.split()[0]} heuristic threat patterns and local URL forensics. English statistical ML model was bypassed to avoid inaccurate cross-lingual predictions."
        }
    else:
        # Tier 3: Unsupported Language / Universal URL Forensics Only
        ml_prob = None
        composite_score = min(round(combined_penalties * 1.5), 100)
        confidence = 0.50

        language_info = {
            "code": "other",
            "name": "Other / Unsupported",
            "tier": "Tier 3 — URL Forensics Only",
            "ml_applied": False,
            "mode": "URL Forensics Only",
            "note": "Limited language analysis: Textual machine learning and heuristic models are not calibrated for this language. Only URL forensics and universal technical patterns were evaluated."
        }

    # Safety Floor: If severe flags are triggered, ensure score reflects high suspicion
    severe_flags = [f for f in detected_flags if "Credential" in f["flag"] or "Untraceable" in f["flag"] or "Bare IP" in f["flag"]]
    if severe_flags and composite_score < 65:
        composite_score = 70
    elif combined_penalties >= 35 and composite_score < 50:
        composite_score = 55

    # Clamp between 0 and 100
    composite_score = max(0, min(100, composite_score))

    # 5. Risk Categorization
    if composite_score >= 70:
        risk_level = "High Risk"
    elif composite_score >= 30:
        risk_level = "Suspicious"
    else:
        risk_level = "Low Risk"

    # 6. Safety Advice
    recommendations = generate_recommendations(risk_level, detected_flags)

    # 7. Truncated snippet for database storage / display
    snippet = content_clean[:200] + ("..." if len(content_clean) > 200 else "")

    return {
        "scan_type": scan_type,
        "input_snippet": snippet,
        "risk_score": composite_score,
        "risk_level": risk_level,
        "confidence_score": confidence,
        "ml_probability": round(ml_prob, 4) if ml_prob is not None else 0.0,
        "ml_applied": (ml_prob is not None),
        "detected_flags": detected_flags,
        "recommendations": recommendations,
        "language_info": language_info,
        "disclaimer": _DISCLAIMER,
    }



_DISCLAIMER = (
    "TrustGuard AI provides probabilistic risk indicators based on algorithmic pattern recognition "
    "and heuristic rules. It does not provide legal, financial, or cybersecurity guarantees of safety "
    "or fraud. Always verify independently before sharing sensitive information or making payments."
)


# Self-test harness for Priority 1 verification
if __name__ == "__main__":
    print("=" * 65)
    print(" TrustGuard AI — Scanner Engine Verification Harness")
    print("=" * 65)

    test_cases = [
        {
            "name": "Benign Casual Message",
            "type": "text",
            "text": "Hi Alex, can you review the project presentation slides before our team meeting at 3pm?"
        },
        {
            "name": "Urgent Banking Phishing Scam",
            "type": "email",
            "text": "URGENT SECURITY ALERT: Your Chase account is suspended. Enter your password and verify your PIN immediately within 24 hours at http://192.168.1.55/login"
        },
        {
            "name": "Job / Internship Upfront Fee Scam",
            "type": "job_offer",
            "text": "Congratulations! You have been selected for a remote Software Engineer internship. Earn $1200/day no experience required. Please transfer a $150 registration fee via gift card or Bitcoin."
        },
        {
            "name": "Deceptive Brand Subdomain URL",
            "type": "url",
            "text": "http://paypal.com.verify-billing-account.xyz/login"
        }
    ]

    for tc in test_cases:
        print(f"\n--- Testing Scenario: {tc['name']} ({tc['type']}) ---")
        result = analyze_content(tc["text"], scan_type=tc["type"])
        print(f"Risk Score : {result['risk_score']}/100 [{result['risk_level']}] (Confidence: {result['confidence_score']})")
        print(f"ML Scam Prob: {result['ml_probability'] * 100:.1f}%")
        print("Detected Flags:")
        if result["detected_flags"]:
            for f in result["detected_flags"]:
                print(f"  * {f['flag']}: {f['description']}")
        else:
            print("  (None)")
        print("Recommendations:")
        for r in result["recommendations"][:2]:
            print(f"  - {r}")
        print(f"Disclaimer : {result['disclaimer'][:75]}...")
