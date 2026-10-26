import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "log-in", "signin", "sign-in", "verify", "verification", "bank",
    "secure", "security", "account", "update", "confirm", "password", "wallet",
    "billing", "invoice", "support", "unlock", "suspended", "limited",
    "paypal", "netflix", "amazon", "appleid", "microsoft", "refund", "prize",
    "winner", "free", "gift", "claim",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "cutt.ly", "rb.gy", "tiny.cc", "shorturl.at", "rebrand.ly",
    "bl.ink", "qr.ae", "shorte.st", "t.ly", "gg.gg",
]

IP_HOST_PATTERN = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

FEATURE_NAMES = [
    "hostname_length", "num_dots", "num_hyphens", "num_digits", "num_special",
    "has_ip", "num_subdomains", "has_at", "keyword_hits", "is_shortener",
    "digit_ratio",
]


def extract_features(raw_url: str) -> list:
    url = raw_url.strip()
    if "://" not in url:
        url = "http://" + url
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        scheme = parsed.scheme.lower()
    except ValueError:
        host, path, scheme = "", "", "http"
    lowered = url.lower()
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)
    special = sum(1 for c in url if not c.isalnum() and c not in ":/.")
    subdomains = max(0, host.count(".") - 1) if host else 0
    return [
        len(host),
        host.count("."),
        host.count("-"),
        digits,
        special,
        1 if IP_HOST_PATTERN.match(host) else 0,
        subdomains,
        1 if "@" in url else 0,
        sum(1 for k in SUSPICIOUS_KEYWORDS if k in lowered),
        1 if any(host == s or host.endswith("." + s) for s in URL_SHORTENERS) else 0,
        round(digits / max(1, letters + digits), 4),
    ]