from flask import Flask, render_template, request
import re 
import sqlite3
from datetime import datetime

app = Flask(__name__)

def create_database():

    conn = sqlite3.connect("phishing.db")

    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT,
        score INTEGER,
        level TEXT,
        scan_date TEXT
    )
    """)

    conn.commit()
    conn.close()

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/history')
def history():

    conn = sqlite3.connect("phishing.db")

    cursor = conn.cursor()

    cursor.execute("""
    SELECT * FROM scans
    ORDER BY id DESC
    """)

    scans = cursor.fetchall()

    conn.close()

    return render_template(
        "history.html",
         scans=scans,
         total_scans=len(scans)
    )


@app.route('/predict', methods=['POST'])
def predict():

    url = request.form['url']

    url_length = len(url)
    dot_count = url.count('.')
    if url.startswith("https://"):
        protocol = "HTTPS"
    elif url.startswith("http://"):
        protocol = "HTTP"
    else:
        protocol = "Unknown"

    score = 0
    reasons = []

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "update",
        "account",
        "banking",
        "password",
        "signin",
        "fake"
    ]

    found_words = []

    shorteners = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "t.co",
    "is.gd"
    ]

    suspicious_tlds = [
    ".xyz",
    ".top",
    ".click",
    ".tk",
    ".gq",
    ".ml",
    ".cf"
    ]

    # Rule 1
    if '@' in url:
        score += 50
        reasons.append("Contains @ symbol")

    # Rule 2
    if '-' in url:
        score += 15
        reasons.append("Contains hyphen (-)")

    # Rule 3
    if len(url) > 50:
        score += 20
        reasons.append("URL is very long")

    # Rule 4
    if url.count('.') > 3:
        score += 20
        reasons.append("Too many dots")

    # Rule 5
    if not url.startswith("https://"):
        score += 15
        reasons.append("Not using HTTPS")

    # IP Address Detection
    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        score += 25
        reasons.append("Uses IP address instead of domain name")    

    # Rule 6
    for word in suspicious_words:
        if word in url.lower():
            score += 15
            reasons.append(f"Contains suspicious word: {word}")
            found_words.append(word)

    # Rule 7 
    shortener_found = "None"

    for shortener in shorteners:
        if shortener in url.lower():
            score += 25
            shortener_found = shortener
            reasons.append(f"Uses URL shortening service: {shortener}")      

    # Rule 8
    for tld in suspicious_tlds:
        if tld in url.lower():
            score += 20
            reasons.append(f"Uses suspicious TLD: {tld}")

    # Rule 9 - Excessive Subdomains
    if dot_count >= 4:
        score += 20
        reasons.append("Contains excessive subdomains")     

    # Rule 10 - URL Encoding Detection
    if "%" in url:
        score += 15
        reasons.append("Contains URL encoded characters")       

    # Prevent score > 100
    if score > 100:
        score = 100

    # Risk Level
    if score >= 70:
        level = "HIGH"
        bar_color = "#ff4d4d"
    elif score >= 30:
        level = "MEDIUM"
        bar_color = "#ffb347"
    else:
        level = "LOW"
        bar_color = "#32cd32"

    # Final Decision
    if score >= 50:
        result = "🚨 Suspicious URL"
        color = "red"
    else:
        result = "✅ URL Looks Safe"
        color = "lime"


    conn = sqlite3.connect("phishing.db")

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO scans(url, score, level, scan_date)
    VALUES (?, ?, ?, ?)
    """, (
        url,
        score,
        level,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()

    return render_template(
        "index.html",
        prediction=result,
        color=color,
        reasons=reasons,
        score=score,
        rules_triggered=len(reasons),
        level=level,
        bar_color=bar_color,
        protocol=protocol,
        url_length=url_length,
        dot_count=dot_count,
        found_words=found_words,
        analyzed_url=url,
        shortener_found=shortener_found
    )
    


create_database()

if __name__ == '__main__':
    app.run(debug=True)