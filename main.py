from flask import Flask, render_template, request
from urllib.parse import urlparse

app = Flask(__name__)

def check_url(url):
    url = url.strip()

    # 🚫 Empty input
    if not url:
        return "INVALID", ["URL cannot be empty"]

    parsed = urlparse(url)

    # 🚫 Not a valid URL
    if not parsed.scheme or not parsed.netloc or "." not in parsed.netloc:
        return "INVALID", [
            "Input is not a valid URL",
            "Only links like https://example.com are allowed"
        ]

    # 🚫 Invalid scheme
    if parsed.scheme not in ["http", "https"]:
        return "INVALID", ["Only HTTP or HTTPS URLs are allowed"]

    reasons = []

    # 🔐 HTTPS check
    if parsed.scheme != "https":
        reasons.append("Uses HTTP instead of HTTPS (not encrypted)")

    # ⚠️ Phishing keywords
    phishing_keywords = [
        "login", "verify", "update", "secure",
        "account", "bank", "confirm", "password"
    ]
    if any(word in url.lower() for word in phishing_keywords):
        reasons.append("Contains suspicious phishing keywords")

    # 🔗 URL shorteners
    shorteners = ["bit.ly", "tinyurl", "t.co"]
    if any(s in parsed.netloc.lower() for s in shorteners):
        reasons.append("Uses shortened URL (can hide real destination)")

    if reasons:
        return "UNSAFE", reasons

    return "SAFE", ["No suspicious patterns detected"]

@app.route("/", methods=["GET", "POST"])
def index():
    status = None
    reasons = []

    if request.method == "POST":
        url = request.form.get("url", "")
        status, reasons = check_url(url)

    return render_template("index.html", status=status, reasons=reasons)

if __name__ == "__main__":
    app.run(debug=True)
