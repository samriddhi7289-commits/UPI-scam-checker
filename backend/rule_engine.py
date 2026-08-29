"""
UPI Scam Pattern Checker — Rule Engine
Rules built from documented 2026 fraud patterns (RBI/NPCI/I4C advisories).
Each rule adds weighted risk points + a human-readable reason.
No AI/ML — fully transparent, explainable scoring.
"""

import re

# ---------------------------------------------------------------------------
# Reference data — edit/extend these lists as you research more patterns
# ---------------------------------------------------------------------------

URGENCY_PHRASES = [
    "verify now", "account will be blocked", "account blocked", "act now",
    "immediately", "within 24 hours", "urgent action required",
    "your account has been suspended", "last warning", "final notice",
    "kyc update", "kyc expired", "update your kyc", "complete your kyc",
    # Hinglish / transliterated Hindi — common in real scam SMS/WhatsApp text
    "turant", "abhi karein", "jaldi karein", "block ho jayega",
    "band ho jayega", "aakhri chetavani", "khata band",
]

REMOTE_ACCESS_APPS = [
    "anydesk", "teamviewer", "quick support", "quicksupport",
    "screen share", "screenshare", "remote access", "team viewer",
]

SENSITIVE_INFO_REQUESTS = [
    "otp", "upi pin", "cvv", "share your pin", "enter your pin",
    "confirm otp", "send otp", "one time password",
    # Hinglish
    "otp bhejo", "pin bataye", "pin batao", "otp share karo",
]

REFUND_TEST_PAYMENT_PHRASES = [
    "refund payment", "verification payment", "processing fee",
    "test transaction", "pay ₹1", "pay rs 1", "pay re 1",
    "to receive your refund", "claim your refund",
    # Hinglish
    "refund paane ke liye", "paisa wapas paane ke liye",
]

FAKE_AUTHORITY_PHRASES = [
    "bank representative", "customer care executive", "rbi officer",
    "npci officer", "calling from your bank", "calling from bank",
    # Hinglish
    "bank se bol raha", "bank se bol rahi",
]

# Legit bank domains — used to catch lookalikes
KNOWN_BANK_DOMAINS = [
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com",
    "kotak.com", "pnbindia.in", "bankofbaroda.in", "npci.org.in",
    "rbi.org.in",
]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "cutt.ly", "t.co", "is.gd", "rb.gy"]

# Suspicious VPA handle patterns: long random alphanumeric, or generic
# 'refund', 'support', 'kyc' style handles
SUSPICIOUS_VPA_PATTERNS = [
    r"refund", r"kyc", r"support\d+", r"[a-z]{2,6}\d{6,}",
]


def _find_matches(text: str, phrase_list):
    text_lower = text.lower()
    return [p for p in phrase_list if p in text_lower]


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if len(b) == 0:
        return len(a)
    prev_row = range(len(b) + 1)
    for i, ca in enumerate(a):
        curr_row = [i + 1]
        for j, cb in enumerate(b):
            insertions = prev_row[j + 1] + 1
            deletions = curr_row[j] + 1
            substitutions = prev_row[j] + (ca != cb)
            curr_row.append(min(insertions, deletions, substitutions))
        prev_row = curr_row
    return prev_row[-1]


def analyze_text(message: str):
    """Analyze free text (SMS/WhatsApp message) for scam indicators."""
    findings = []
    score = 0

    urgency_hits = _find_matches(message, URGENCY_PHRASES)
    if urgency_hits:
        score += 20
        findings.append({
            "reason": f"Urgency/pressure language detected: \"{urgency_hits[0]}\"",
            "weight": 20,
            "category": "urgency"
        })

    remote_hits = _find_matches(message, REMOTE_ACCESS_APPS)
    if remote_hits:
        score += 35
        findings.append({
            "reason": f"Mentions remote access app: \"{remote_hits[0]}\" — legitimate banks never ask you to install these",
            "weight": 35,
            "category": "remote_access"
        })

    info_hits = _find_matches(message, SENSITIVE_INFO_REQUESTS)
    if info_hits:
        score += 35
        findings.append({
            "reason": f"Requests sensitive info: \"{info_hits[0]}\" — never shared to receive money",
            "weight": 35,
            "category": "sensitive_info"
        })

    refund_hits = _find_matches(message, REFUND_TEST_PAYMENT_PHRASES)
    if refund_hits:
        score += 30
        findings.append({
            "reason": f"Fake refund/verification payment pattern: \"{refund_hits[0]}\" — receiving money never requires you to pay first",
            "weight": 30,
            "category": "fake_refund"
        })

    authority_hits = _find_matches(message, FAKE_AUTHORITY_PHRASES)
    if authority_hits:
        score += 15
        findings.append({
            "reason": f"Claims to be a bank/authority representative: \"{authority_hits[0]}\"",
            "weight": 15,
            "category": "fake_authority"
        })

    # small-amount "test" transaction mention
    amount_matches = re.findall(r"(?:rs\.?|₹|inr)\s?(\d+)", message.lower())
    if amount_matches and any(int(a) < 10 for a in amount_matches):
        score += 15
        findings.append({
            "reason": "Mentions a very small amount (< ₹10) — a known tactic to authorize a larger hidden debit",
            "weight": 15,
            "category": "micro_transaction"
        })

    return score, findings


def analyze_vpa(vpa: str):
    """Analyze a UPI ID / VPA for suspicious patterns."""
    findings = []
    score = 0
    vpa_lower = vpa.lower().strip()

    if "@" not in vpa_lower:
        return 0, [{
            "reason": "Not a valid UPI ID format (missing '@handle')",
            "weight": 0,
            "category": "invalid_format"
        }]

    local_part, handle = vpa_lower.split("@", 1)

    for pattern in SUSPICIOUS_VPA_PATTERNS:
        if re.search(pattern, local_part):
            score += 25
            findings.append({
                "reason": f"UPI ID contains a suspicious pattern typical of scam/mule accounts: matched '{pattern}'",
                "weight": 25,
                "category": "suspicious_vpa"
            })
            break  # one hit is enough signal, avoid double counting

    if len(local_part) > 15 and any(c.isdigit() for c in local_part):
        score += 15
        findings.append({
            "reason": "Long alphanumeric UPI handle — common in freshly created mule accounts",
            "weight": 15,
            "category": "suspicious_vpa"
        })

    return score, findings


def analyze_url(url: str):
    """Analyze a URL for phishing/lookalike domain patterns."""
    findings = []
    score = 0
    url_lower = url.lower().strip()

    for shortener in URL_SHORTENERS:
        if shortener in url_lower:
            score += 25
            findings.append({
                "reason": f"Uses a URL shortener ({shortener}) — hides the real destination, common in phishing links",
                "weight": 25,
                "category": "shortened_url"
            })
            break

    # extract domain roughly
    domain_match = re.search(r"https?://([^/]+)", url_lower)
    domain = domain_match.group(1) if domain_match else url_lower

    for real_domain in KNOWN_BANK_DOMAINS:
        base_name = real_domain.split(".")[0]
        if base_name in domain and domain != real_domain and not domain.endswith("." + real_domain):
            score += 40
            findings.append({
                "reason": f"Domain '{domain}' closely resembles official bank domain '{real_domain}' but does not match exactly — likely lookalike/phishing site",
                "weight": 40,
                "category": "lookalike_domain"
            })
            break
        dist = _levenshtein(domain, real_domain)
        if 0 < dist <= 2:
            score += 40
            findings.append({
                "reason": f"Domain '{domain}' is a near-exact match (typo-squat) of '{real_domain}'",
                "weight": 40,
                "category": "lookalike_domain"
            })
            break

    return score, findings


def get_risk_level(score: int) -> str:
    if score >= 50:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "SAFE"


def extract_upi_id_from_qr_string(qr_text: str):
    """
    Parses a decoded UPI QR payload (upi://pay?pa=...&pn=...) and pulls out
    the VPA (pa param). Returns None if it doesn't look like a UPI QR at all.
    """
    if not qr_text:
        return None
    match = re.search(r"[?&]pa=([^&\s]+)", qr_text)
    if match:
        return match.group(1)
    # some QR codes just encode the raw VPA with no upi:// wrapper
    if "@" in qr_text and " " not in qr_text.strip():
        return qr_text.strip()
    return None


def analyze_batch(input_type: str, values: list):
    """Run analyze_input over a list of values, one result per line."""
    results = []
    for v in values:
        v = v.strip()
        if not v:
            continue
        results.append(analyze_input(input_type, v))
    return results


def analyze_input(input_type: str, value: str):
    """
    Main entry point.
    input_type: 'text' | 'vpa' | 'url'
    Returns dict with score, risk level, and list of findings.
    """
    if input_type == "text":
        score, findings = analyze_text(value)
    elif input_type == "vpa":
        score, findings = analyze_vpa(value)
    elif input_type == "url":
        score, findings = analyze_url(value)
    else:
        raise ValueError(f"Unknown input_type: {input_type}")

    score = min(score, 100)  # cap at 100

    return {
        "input_type": input_type,
        "value": value,
        "score": score,
        "risk_level": get_risk_level(score),
        "findings": findings,
    }
