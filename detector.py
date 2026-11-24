"""WebGuard detection engine: analyzes URLs and messages and returns a risk score."""
import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {"zip", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "work", "support", "info", "buzz", "country"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at"}
BRAND_KEYWORDS = ["paypal", "amazon", "google", "microsoft", "apple", "facebook", "instagram",
                  "netflix", "sbi", "hdfc", "icici", "paytm", "phonepe", "whatsapp", "flipkart"]
URL_WORDS = ["login", "verify", "update", "secure", "account", "banking", "confirm", "signin", "password", "wallet"]

MESSAGE_RULES = [
    (r"\b(urgent|immediately|right now|within 24 hours|act now|last warning|final notice)\b", 15, "Creates urgency or pressure"),
    (r"\b(verify|confirm|update|validate)\b.{0,30}\b(account|password|details|kyc|identity|card)\b", 20, "Asks you to verify or update account details"),
    (r"\b(suspended|blocked|locked|deactivated|restricted|limited)\b", 15, "Threatens account suspension or blocking"),
    (r"\b(otp|cvv|pin|password|passcode)\b", 20, "Asks for sensitive info (OTP, PIN, CVV, password)"),
    (r"\b(winner|won|prize|lottery|reward|gift card|free|cashback|congratulations)\b", 15, "Offers prizes, rewards or free items"),
    (r"\b(click|tap|open)\b.{0,20}\b(link|here|below)\b", 10, "Pushes you to click a link"),
    (r"\b(dear (customer|user|member)|valued customer)\b", 8, "Uses generic greeting instead of your name"),
    (r"\b(bank|kyc|pan card|aadhaar|upi)\b", 8, "Mentions banking/identity details"),
    (r"\b(refund|payment (failed|pending)|invoice|unauthori[sz]ed (transaction|login))\b", 10, "Mentions refunds, failed payments or unauthorized activity"),
]

URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)


def risk_category(score: int) -> str:
    if score >= 60:
        return "HIGH RISK"
    if score >= 30:
        return "MEDIUM RISK"
    return "LOW RISK"


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))


def analyze_url(url: str) -> dict:
    """Return {'score': int, 'reasons': [str]} for a single URL."""
    reasons, score = [], 0
    raw = url.strip()
    if not re.match(r"^https?://", raw, re.IGNORECASE):
        raw = "http://" + raw
    parsed = urlparse(raw)
    host = (parsed.hostname or "").lower()
    full = raw.lower()

    if not host:
        return {"score": 50, "reasons": ["URL could not be parsed properly"]}

    if parsed.scheme == "http":
        score += 10
        reasons.append("Does not use HTTPS (connection not encrypted)")
    if _is_ip(host):
        score += 30
        reasons.append("Uses an IP address instead of a domain name")
    if "@" in parsed.netloc:
        score += 25
        reasons.append("Contains '@' symbol (can hide the real destination)")
    if len(raw) > 75:
        score += 10
        reasons.append(f"Very long URL ({len(raw)} characters)")
    if host in URL_SHORTENERS:
        score += 20
        reasons.append("Uses a URL shortener that hides the real destination")
    if "xn--" in host:
        score += 20
        reasons.append("Uses punycode (possible look-alike characters)")

    parts = host.split(".")
    tld = parts[-1] if len(parts) > 1 else ""
    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Uses a commonly abused domain ending (.{tld})")
    if len(parts) > 4:
        score += 15
        reasons.append("Too many subdomains")
    if host.count("-") >= 2:
        score += 10
        reasons.append("Many hyphens in the domain name")
    if re.search(r"\d", parts[-2] if len(parts) > 1 else host) and not _is_ip(host):
        score += 5
        reasons.append("Digits inside the domain name")

    # Brand name appearing outside the real registered domain (e.g. paypal.secure-login.xyz)
    registered = ".".join(parts[-2:]) if len(parts) >= 2 else host
    for brand in BRAND_KEYWORDS:
        if brand in host and not registered.startswith(brand + "."):
            score += 25
            reasons.append(f"Impersonates a brand name ('{brand}') on an unrelated domain")
            break

    hits = [w for w in URL_WORDS if w in full]
    if hits:
        score += min(5 * len(hits), 15)
        reasons.append("Suspicious keywords in URL: " + ", ".join(hits[:4]))

    return {"score": min(score, 100), "reasons": reasons}


def analyze_message(text: str) -> dict:
    """Analyze message text (and any URLs inside it). Returns score, reasons, urls."""
    reasons, score = [], 0
    lowered = text.lower()

    for pattern, points, reason in MESSAGE_RULES:
        if re.search(pattern, lowered, re.IGNORECASE | re.DOTALL):
            score += points
            reasons.append(reason)

    letters = [c for c in text if c.isalpha()]
    if len(letters) > 20 and sum(c.isupper() for c in letters) / len(letters) > 0.5:
        score += 8
        reasons.append("Excessive use of CAPITAL LETTERS")
    if text.count("!") >= 3:
        score += 5
        reasons.append("Excessive exclamation marks")

    urls = URL_REGEX.findall(text)
    url_results = []
    for u in urls:
        u = u.rstrip(".,;)")
        res = analyze_url(u)
        url_results.append({"url": u, **res})
    if url_results:
        worst = max(r["score"] for r in url_results)
        score += int(worst * 0.6)
        reasons.append(f"Contains {len(url_results)} link(s); riskiest link scored {worst}/100")

    return {"score": min(score, 100), "reasons": reasons, "urls": url_results}


def safety_advice(category: str) -> list:
    if category == "HIGH RISK":
        return [
            "Do NOT click any links or open attachments.",
            "Never share OTP, PIN, CVV or passwords.",
            "Report it (India: cybercrime.gov.in or call 1930) and delete the message.",
            "If you already clicked, change your passwords and contact your bank immediately.",
        ]
    if category == "MEDIUM RISK":
        return [
            "Be careful. Verify the sender through an official website or app.",
            "Don't click links; type the official address in your browser yourself.",
            "Contact the organization using the number on its official site.",
        ]
    return [
        "No major red flags found, but stay alert.",
        "Always check the sender and the URL before entering any details.",
    ]
