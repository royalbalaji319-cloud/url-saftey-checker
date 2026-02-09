import re
from urllib.parse import urlparse

def is_valid_url(url):
    pattern = re.compile(
        r'^(https?:\/\/)?'              # http or https (optional)
        r'([\da-z.-]+)\.'               # domain name
        r'([a-z.]{2,6})'                # TLD
        r'([\/\w .-]*)*\/?$'            # path
    )
    return re.match(pattern, url)


def check_url_safety(url):
    url = url.strip()
    reasons = []

    # ❌ If not a valid URL
    if not is_valid_url(url):
        return "INVALID", ["Please enter a valid URL (example: https://example.com)"]

    parsed = urlparse(url if url.startswith("http") else "http://" + url)

    # Protocol check
    if parsed.scheme != "https":
        reasons.append("Uses HTTP or no HTTPS (not encrypted)")

    # URL shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co"]
    if any(s in parsed.netloc for s in shorteners):
        reasons.append("Uses URL shortener (destination hidden)")

    # Risky domains
    risky_tlds = [".xyz", ".top", ".info", ".site"]
    if any(parsed.netloc.endswith(tld) for tld in risky_tlds):
        reasons.append("High-risk domain extension")

    # Suspicious keywords
    keywords = ["free", "money", "login", "verify", "update", "otp", "reward"]
    if any(k in url.lower() for k in keywords):
        reasons.append("Contains suspicious keywords")

    # IP-based URL
    if re.match(r"\d+\.\d+\.\d+\.\d+", parsed.netloc):
        reasons.append("Uses IP address instead of domain")

    status = "UNSAFE" if len(reasons) >= 2 else "SAFE"
    return status, reasons
