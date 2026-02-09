from urllib.parse import urlparse
import re

def check_url(url):
    url = url.strip()

    # 🚫 Empty input
    if not url:
        return "INVALID", ["URL cannot be empty"]

    parsed = urlparse(url)

    # 🚫 Not a URL at all
    # Must have scheme AND domain AND dot in domain
    if not parsed.scheme or not parsed.netloc or "." not in parsed.netloc:
        return "INVALID", [
            "Input is not a valid URL",
            "Only links like https://example.com are allowed"
        ]

    # 🚫 Scheme must be http or https
    if parsed.scheme not in ["http", "https"]:
        return "INVALID", ["Only HTTP or HTTPS URLs are allowed"]

    reasons = []

    # 🔐 HTTPS check
    if parsed.scheme != "https":
        reasons.append("Uses HTTP or no HTTPS (not encrypted)")

    # ⚠️ Suspicious keywords
    phishing_keywords = [
        "login", "verify", "update", "secure",
        "account", "bank", "confirm", "password"
    ]
    if any(word in url.lower() for word in phishing_keywords):
        reasons.append("Contains suspicious keywords")

    # 🔗 URL shorteners
    shorteners = ["bit.ly", "tinyurl", "t.co"]
    if any(s in parsed.netloc.lower() for s in shorteners):
        reasons.append("Uses shortened URL (can hide real destination)")

    if reasons:
        return "UNSAFE", reasons

    return "SAFE", ["No suspicious patterns detected"]
