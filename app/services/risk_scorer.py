import re
from urllib.parse import urlparse
from email.utils import parseaddr
from app.config import Config
from app.services.email_parser import EmailParser

SUSPICIOUS_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".zip"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly"}

PHISH_KEYWORDS = [
    "urgent", "important", "verify", "verify now", "account suspended",
    "click here", "immediate action", "password reset", "limited time",
    "confirm your identity", "unusual login", "payment failed",
    "invoice attached", "bank account", "security alert", "account locked",
    "compromised", "login", "update your details", "confirm your account",
    "claim your prize", "free iphone", "winner", "act now"
]

GENERIC_GREETINGS = [
    "dear user", "dear customer", "dear client", "hello user",
    "valued customer"
]

SENSITIVE_REQUESTS = [
    "username", "password", "credit card", "card number", "pin",
    "bank details", "social security", "login information"
]

BRANDS = {
    "microsoft": "microsoft.com",
    "google": "google.com",
    "paypal": "paypal.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "outlook": "outlook.com",
    "office365": "microsoft.com"
}


def get_domain(email_address):
    _, addr = parseaddr(email_address or "")
    if "@" in addr:
        return addr.split("@")[-1].lower()
    return ""


def analyze_headers(headers):
    score = 0
    reasons = []

    from_field = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    return_path = headers.get("Return-Path", "")
    auth_results = str(headers.get("Authentication-Results", "")).lower()

    from_domain = get_domain(from_field)
    reply_domain = get_domain(reply_to)
    return_domain = get_domain(return_path)

    internal_domains = [d.lower() for d in getattr(Config, "INTERNAL_DOMAINS", [])]

    if not from_domain:
        score += 20
        reasons.append("Sender domain could not be identified")
        external = True
    elif from_domain not in internal_domains:
        score += 25
        reasons.append(f"External sender detected: {from_domain}")
        external = True
    else:
        external = False
        reasons.append("Internal sender")

    if "spf=fail" in auth_results:
        score += 35
        reasons.append("SPF authentication failed")

    if "dkim=fail" in auth_results:
        score += 35
        reasons.append("DKIM authentication failed")

    if "dmarc=fail" in auth_results:
        score += 40
        reasons.append("DMARC authentication failed")

    if reply_domain and from_domain and reply_domain != from_domain:
        score += 30
        reasons.append(f"Reply-To mismatch: {reply_domain} differs from {from_domain}")

    if return_domain and from_domain and return_domain != from_domain:
        score += 25
        reasons.append(f"Return-Path mismatch: {return_domain} differs from {from_domain}")

    for brand, official_domain in BRANDS.items():
        if brand in from_domain and from_domain != official_domain:
            score += 35
            reasons.append(f"Possible {brand} sender impersonation")

    return {
        "score": min(score, 100),
        "reasons": reasons,
        "from_domain": from_domain,
        "external": external
    }


def check_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace("www.", "")
    score = 0
    reasons = []

    if not domain:
        return {
            "url": url,
            "domain": domain,
            "score": 15,
            "reasons": ["Malformed URL"]
        }

    score += 15
    reasons.append("Email contains a link")

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 35
        reasons.append("Suspicious top-level domain")

    if domain in URL_SHORTENERS:
        score += 30
        reasons.append("URL shortener detected")

    if re.search(r"\d+\.\d+\.\d+\.\d+", domain):
        score += 35
        reasons.append("URL uses IP address instead of domain name")

    if "@" in url:
        score += 35
        reasons.append("URL contains @ symbol redirection trick")

    if len(url) > 100:
        score += 20
        reasons.append("Unusually long URL")

    for brand, official_domain in BRANDS.items():
        if brand in domain and not domain.endswith(official_domain):
            score += 40
            reasons.append(f"Possible fake {brand} link")

    return {
        "url": url,
        "domain": domain,
        "score": min(score, 100),
        "reasons": reasons
    }


def analyze_text(body):
    text = str(body).lower()
    score = 0
    reasons = []

    keyword_matches = [kw for kw in PHISH_KEYWORDS if kw in text]
    greeting_matches = [g for g in GENERIC_GREETINGS if g in text]
    sensitive_matches = [s for s in SENSITIVE_REQUESTS if s in text]

    if keyword_matches:
        score += min(len(keyword_matches) * 12, 50)
        reasons.append(f"Phishing keywords found: {', '.join(keyword_matches)}")

    if greeting_matches:
        score += 15
        reasons.append(f"Generic greeting found: {', '.join(greeting_matches)}")

    if sensitive_matches:
        score += 35
        reasons.append(f"Sensitive information requested: {', '.join(sensitive_matches)}")

    if re.search(r"\b(act now|immediately|within 24 hours|account will be locked|avoid suspension)\b", text):
        score += 30
        reasons.append("Urgency or threat language detected")

    if re.search(r"\b(won|winner|free|prize|reward|gift card)\b", text):
        score += 25
        reasons.append("Too-good-to-be-true offer detected")

    if re.search(r"\b(accunt|suspecious|verfy|passwrod|recieve)\b", text):
        score += 20
        reasons.append("Spelling mistakes commonly seen in phishing emails detected")

    return {
        "score": min(score, 100),
        "matches": keyword_matches,
        "reasons": reasons
    }


def calculate_risk(raw_email):
    parser = EmailParser(raw_email)
    headers = parser.get_headers()
    body = parser.get_body()
    urls = parser.extract_urls(body)

    header_result = analyze_headers(headers)
    text_result = analyze_text(body)
    url_results = [check_url(url) for url in urls]

    url_score = max([u["score"] for u in url_results], default=0)

    total_score = (
        header_result["score"] * 0.35 +
        text_result["score"] * 0.35 +
        url_score * 0.30
    )

    if urls and text_result["score"] >= 25:
        total_score += 15

    if header_result["external"] and urls:
        total_score += 10

    total_score = min(round(total_score, 1), 100)

    if total_score >= 60:
        risk = "HIGH"
        color = "danger"
    elif total_score >= 30:
        risk = "MEDIUM"
        color = "warning"
    else:
        risk = "LOW"
        color = "success"

    return {
        "risk_level": risk,
        "color": color,
        "score": total_score,
        "details": {
            "headers": header_result,
            "keywords": text_result,
            "urls": url_results,
            "external_sender": header_result["external"],
            "link_count": len(urls)
        }
    }