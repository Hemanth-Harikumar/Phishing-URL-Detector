# Phishing URL Detector

A Flask app that scores a URL with a hostname-based Random Forest classifier, explains the score (SHAP or feature importance), and keeps a scan history. It is an **academic triage tool**: URL-only, no network lookups, no page content.

## What changed in this version
- **Brand-impersonation features** (`ml/brands.py`): brand name in a subdomain (`paypal.com.secure-login.tk`), brand inside an unrelated registrable domain (`secure-chase-banking.com`), and look-alike spellings (`paypa1`, `amaz0n`, `micros0ft`) using leet-normalisation and edit distance against ~45 hand-picked brands.
- **Small allowlist** of well-known brand domains. Exact registrable-domain match only, and **never** applied to user-content hosts (`sites.google.com`, `*.sharepoint.com`, `github.io`, ...), where phishing is commonly hosted. An allowlisted verdict overrides the model and the UI says so; the raw model score is still shown.
- **Threshold chosen on a validation split**, not by hand and not on the test split. Training now uses a three-way split grouped by registrable domain (train / validation / test).
- **Clean holdout** (`data/evaluation/holdout_legitimate.csv`): 146 URLs on 73 domains that were removed from training and scored once.
- Hostname-only, scheme- and `www`-invariant features (from the previous version) so the model cannot key on dataset artifacts such as `https://www.`.
- Automated tests, a development-only random secret key when none is configured, and a timeout on the optional LLM call.

## Results (read the limitations below)
Held-out test split (domain-grouped, scored once, threshold 0.71 chosen on validation with target FPR <= 2%):

| Metric | Threshold 0.71 | Threshold 0.50 |
|---|---|---|
| Accuracy | 82.2% | 81.0% |
| Precision (phishing) | 95.6% | 83.2% |
| Recall (phishing) | 55.7% | 62.7% |
| False-positive rate (legitimate flagged) | 1.6% | 7.7% |
| ROC-AUC | 0.823 | |

Legitimate-only checks at the same threshold (these say nothing about recall):

| Set | URLs / domains | False positives (model only) | After allowlist |
|---|---|---|---|
| Clean holdout (domain-disjoint, scored once) | 146 / 73 | 3 (2.1%) | n/a |
| Development probe (overlaps development) | 280 / 35 | 40 (14.3%), on 14 domains | 28 (10.0%) |

## Limitations
- **Recall is low (about 56% on the test split).** Hostname features alone miss many phishing URLs whose hostnames look ordinary. The threshold trades recall for fewer false alarms. Do not call this a complete detector.
- **The two legitimate-only sets disagree** (2.1% vs 14.3%). Both are hand-assembled and small, so treat false-positive rates as rough. The probe contains harder security/tech sites and was looked at during development.
- **No independent phishing benchmark yet.** The test split comes from the same dataset as training. A real evaluation needs a current legitimate list (e.g. Tranco) plus an independent, dated phishing feed (PhishTank/OpenPhish), de-duplicated by registrable domain.
- **Registrable domains use a small built-in suffix list**, not the full Public Suffix List. The brand list and allowlist are hand-maintained and incomplete.
- Look-alike matching can false-positive on real words close to a brand name (for example a short word one edit from `apple`). The model weighs it; it is not a hard rule.
- PhiUSIIL contains dataset artifacts. Earlier versions scored 99.6% by exploiting them; those numbers do not reflect real-world accuracy.

## Quick start (Windows / VS Code)
Use Python 3.11 or 3.12.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`. The trained model is bundled. If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process Bypass`.

## Retraining
The 56 MB PhiUSIIL CSV is not bundled. Download it and retrain:

```powershell
python train_model.py --download-uci
python train_model.py --extra-legitimate data/evaluation/curated_legitimate_training.csv
```
By default the threshold is chosen on a validation split (`--target-fpr 0.02`); pass `--threshold` to fix it. `--max-rows` (default 100000) samples the large source for speed; use `0` for all rows. Training writes `models/phishing_model.joblib`, `reports/training_metrics.json` and `reports/holdout_metrics.json`. Domains in the holdout file are removed from training automatically. Re-score the development probe with `python evaluate_probe_set.py`.

## Optional LLM security reports
Copy `.env.example` to `.env` and set `OPENAI_API_KEY`, `OPENAI_MODEL` and `FLASK_SECRET_KEY`. Keep `.env` private. Without a key a local evidence-based report is shown. The URL is passed to the LLM as untrusted data and the LLM never changes the verdict.

## Architecture
1. `app.py` validates the URL (no network request).
2. `ml/url_features.py` extracts 23 hostname-focused, scheme-invariant features.
3. `ml/brands.py` provides brand-impersonation signals, the registrable-domain helper and the allowlist.
4. `ml/model_service.py` runs the Random Forest, applies the validation-chosen threshold and the allowlist override.
5. SHAP explains predictions where supported, otherwise the UI labels a feature-importance fallback.
6. `ml/reporting.py` builds the local or optional LLM report. History is stored in SQLite.

## Tests
```powershell
python -m unittest discover -s tests -v
```
25 tests cover feature extraction and schema, brand/allowlist logic (including user-content hosts), model behaviour (allowlist override, impersonation patterns, scheme/`www` invariance) and app helpers.

## Dataset citation
Prasad, A. & Chandra, S. (2024). *PhiUSIIL: Phishing URL (Website) Dataset*. UCI Machine Learning Repository. https://doi.org/10.1016/j.cose.2023.103545. License: CC BY 4.0. See `LICENSE-DATASET.txt`.

## Safe use
Not a security guarantee. Do not use the output as the sole basis for blocking a URL or handling an incident. For public deployment set `APP_ENV=production`, provide a persistent `FLASK_SECRET_KEY` of at least 32 characters, enable HTTPS and `COOKIE_SECURE=1`, and run behind a production WSGI server. CSRF protection and basic in-process rate limiting are implemented; the latter should be replaced with shared storage for multi-worker deployments.

## v5.1 maintenance update

- Fixed suspicious-host keyword normalization: only an exact leading `www.` is removed, so hostnames such as `wallet.com` are no longer accidentally altered by character-set stripping.
- Moved URL validation and risk-label helpers into `ml/web_helpers.py` so they can be tested without importing the Flask web server.
- Added regression tests for suspicious-host keyword normalization.
- The automated test suite currently passes in the review environment. The Flask web interface still needs an end-to-end run in an environment with the dependencies from `requirements.txt` installed.

Run tests with:

```bash
python -m pip install -r requirements.txt
python -m pytest -q
```

For local use, start the app with `python app.py` and open `http://127.0.0.1:5000`.


## Production configuration (Windows / PowerShell)

The app now refuses to start in production mode without a persistent secret key. Generate one once and store it securely as an environment variable; do not commit it to Git:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
$env:APP_ENV = "production"
$env:FLASK_SECRET_KEY = "paste-the-generated-value-here"
$env:COOKIE_SECURE = "1"
$env:PORT = "8080"
python app.py
```

Use `COOKIE_SECURE=1` only when the app is accessed through HTTPS. For local HTTP testing, leave `COOKIE_SECURE` unset/`0`; browsers will not send Secure cookies over plain HTTP. In production, terminate HTTPS at a trusted reverse proxy or hosting platform. The built-in production startup uses Waitress, which is included in `requirements.txt`. Never use the Flask development server for public traffic. Keep `.env` and secret values out of version control.

For multi-worker or multi-instance deployments, replace the in-memory rate limiter with a shared backend such as Redis and configure trusted proxy handling deliberately. Do not trust arbitrary forwarded client-IP headers.

## v5.2 hardening and final verification notes
- Added a session-bound CSRF token to the scan form and reject POST requests with missing/invalid tokens.
- Added baseline security headers, HTTP-only/SameSite session cookies, configurable Secure cookies for HTTPS, and a request-size limit.
- Fixed the missing `urlsplit` import used by the `/predict` route when building URL analysis details.
- The built-in Flask server is for local development only. For public deployment, set a strong persistent `FLASK_SECRET_KEY`, set `COOKIE_SECURE=1` behind HTTPS, and use a production WSGI server.
- Live browser testing is still required after installing dependencies; unit/model tests alone do not certify production readiness.
