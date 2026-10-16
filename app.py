from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
import sqlite3
import secrets
import hmac
import os
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

from ml.model_service import PhishingModel, ModelNotReadyError
from ml.reporting import generate_report
from ml.url_features import extract_url_features, suspicious_host_words
from ml.web_helpers import validate_url, risk_level

DB_PATH = ROOT / "phishing.db"
app = Flask(__name__)
APP_ENV = os.environ.get("APP_ENV", "development").strip().lower()
IS_PRODUCTION = APP_ENV == "production"
_configured_secret = os.environ.get("FLASK_SECRET_KEY", "").strip()
if IS_PRODUCTION and len(_configured_secret) < 32:
    raise RuntimeError(
        "Production requires FLASK_SECRET_KEY to be set to a persistent random value "
        "of at least 32 characters. Generate one with the command: secrets.token_hex(32)."
    )
app.secret_key = _configured_secret or secrets.token_hex(32)
# Set COOKIE_SECURE=1 when served over HTTPS. Production deployments must use HTTPS.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0").lower() in {"1", "true", "yes"},
    MAX_CONTENT_LENGTH=16 * 1024,
)
_model = None
_model_error = None

# ---------------------------------------------------------------------------
# Simple in-memory sliding-window rate limiter (per remote IP).
# Limits the /predict endpoint to RATE_LIMIT_MAX requests per RATE_LIMIT_WINDOW
# seconds. No external dependency required.
# ---------------------------------------------------------------------------
_rate_lock = threading.Lock()
_request_times: dict[str, list[float]] = defaultdict(list)
RATE_LIMIT_WINDOW = 60   # seconds
RATE_LIMIT_MAX = 30      # max requests per window


def _csrf_token() -> str:
    """Create or return a per-session token used to protect the scan form."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": _csrf_token}


@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; form-action 'self'; base-uri 'self'; frame-ancestors 'none'"
    )
    if IS_PRODUCTION and request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response


def _check_rate_limit(ip: str) -> bool:
    """Return True if the request is allowed, False if the rate limit is exceeded."""
    now = time.monotonic()
    with _rate_lock:
        times = _request_times[ip]
        # Evict timestamps older than the window
        times[:] = [t for t in times if now - t < RATE_LIMIT_WINDOW]
        if len(times) >= RATE_LIMIT_MAX:
            return False
        times.append(now)
        return True


# ---------------------------------------------------------------------------
# Model singleton
# ---------------------------------------------------------------------------

def get_model():
    global _model, _model_error
    if _model is None and _model_error is None:
        try:
            _model = PhishingModel()
        except Exception as exc:
            _model_error = str(exc)
    if _model is None:
        raise ModelNotReadyError(_model_error or "Model is not ready")
    return _model


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def create_database():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            level TEXT NOT NULL,
            scan_date TEXT NOT NULL,
            prediction TEXT DEFAULT '',
            probability REAL DEFAULT 0
        )""")
        # Migrate existing installations without deleting previous history.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()}
        if "prediction" not in columns:
            conn.execute("ALTER TABLE scans ADD COLUMN prediction TEXT DEFAULT ''")
        if "probability" not in columns:
            conn.execute("ALTER TABLE scans ADD COLUMN probability REAL DEFAULT 0")


# ---------------------------------------------------------------------------
# Validation and risk helpers
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def home():
    try:
        get_model()
        model_ready = True
        model_error = None
    except ModelNotReadyError as exc:
        model_ready = False
        model_error = str(exc)
    return render_template("index.html", model_ready=model_ready, model_error=model_error)


@app.route('/history')
def history():
    with sqlite3.connect(DB_PATH) as conn:
        scans = conn.execute(
            "SELECT id, url, score, level, scan_date, prediction, probability "
            "FROM scans ORDER BY id DESC"
        ).fetchall()
    return render_template("history.html", scans=scans, total_scans=len(scans))


@app.route('/predict', methods=['POST'])
def predict():
    # Reject cross-site form submissions. Compare tokens in constant time.
    submitted_token = request.form.get("csrf_token", "")
    expected_token = session.get("csrf_token", "")
    if not expected_token or not submitted_token or not hmac.compare_digest(submitted_token, expected_token):
        abort(400, description="Invalid or missing security token. Reload the page and try again.")

    # Rate limiting
    client_ip = request.remote_addr or "unknown"
    if not _check_rate_limit(client_ip):
        flash(
            f"Too many requests. Please wait before scanning again "
            f"(limit: {RATE_LIMIT_MAX} scans per {RATE_LIMIT_WINDOW}s).",
            "error",
        )
        return redirect(url_for('home'))

    url, error = validate_url(request.form.get('url', ''))
    if error:
        flash(error, "error")
        return redirect(url_for('home'))

    try:
        model = get_model()
        result = model.predict(url)
        explanations, explanation_method = model.explain(url)
    except ModelNotReadyError as exc:
        flash(f"ML model is not ready: {exc}", "error")
        return redirect(url_for('home'))

    known_domain = result.get("known_domain", False)
    # Allowlisted well-known domains get a verdict override; the raw model score is shown separately.
    score = 0 if known_domain else result["risk_score"]
    level, bar_color = risk_level(score)
    is_phishing = result["is_phishing"]

    if known_domain:
        prediction, color = "✅ Known Legitimate Domain (allowlist)", "lime"
    elif is_phishing:
        prediction, color = "🚨 Likely Phishing URL", "red"
    elif result.get("needs_review"):
        prediction, color = "⚠️ Uncertain — Manual Review Recommended", "orange"
    else:
        prediction, color = "✅ No Strong Phishing Signals Detected", "lime"

    report, report_source = generate_report(url, result, explanations, explanation_method)
    features = extract_url_features(url)

    parsed = urlsplit(url)
    protocol = parsed.scheme.upper()

    shorteners = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly", "buff.ly", "cutt.ly"}
    shortener_found = (
        parsed.hostname.lower()
        if parsed.hostname and parsed.hostname.lower() in shorteners
        else "None"
    )

    # Re-use the hostname extracted during feature computation to stay consistent
    # with how SUSPICIOUS_HOST_WORDS is applied in url_features.py (hostname-only,
    # www-stripped). This avoids duplicating the keyword list in two places.
    suspicious_words = suspicious_host_words(parsed.hostname or "")

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO scans(url, score, level, scan_date, prediction, probability) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (url, score, level, datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
             prediction, result["phishing_probability"]),
        )

    return render_template(
        "index.html",
        model_ready=True,
        prediction=prediction,
        color=color,
        reasons=[f"{x['feature']}: {x['direction']} (value {x['value']})" for x in explanations],
        explanations=explanations,
        explanation_method=explanation_method,
        report=report,
        report_source=report_source,
        score=score,
        probability=round(result["phishing_probability"] * 100, 2),
        rules_triggered=len(explanations),
        level=level,
        bar_color=bar_color,
        protocol=protocol,
        url_length=len(url),
        dot_count=url.count('.'),
        found_words=suspicious_words,
        analyzed_url=url,
        known_domain=known_domain,
        registrable_domain=result.get("registrable_domain", ""),
        brand_detail=result.get("brand_detail", ""),
        shortener_found=shortener_found,
        features=features,
    )


create_database()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", "5000"))
    if IS_PRODUCTION:
        # Waitress is a production WSGI server that also runs on Windows.
        from waitress import serve
        serve(app, host=os.environ.get("HOST", "0.0.0.0"), port=port)
    else:
        # Local development only; never expose this server publicly.
        app.run(host=os.environ.get("HOST", "127.0.0.1"), port=port, debug=False)
