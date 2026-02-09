from flask import Flask, render_template, request
from checker import check_url_safety   # 👈 IMPORTANT

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    status = None
    reasons = []
    url = ""

    if request.method == "POST":
        url = request.form["url"]
        status, reasons = check_url_safety(url)

    return render_template("index.html", status=status, reasons=reasons, url=url)

if __name__ == "__main__":
    app.run(debug=True)
