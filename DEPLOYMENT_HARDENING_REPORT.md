# v5.3 Deployment Hardening Report

## Changes made
- Production mode is controlled by `APP_ENV=production`.
- Production startup now fails closed unless `FLASK_SECRET_KEY` is configured with at least 32 characters. Development mode retains a random per-process key for local testing.
- Added a Content Security Policy compatible with the current local stylesheet and inline progress-bar style, plus HSTS on production HTTPS requests.
- Added Waitress to requirements and made `python app.py` use Waitress when `APP_ENV=production`; local development continues to use Flask's development server on `127.0.0.1`.
- Updated README deployment guidance, including HTTPS and in-memory rate-limit caveats.
- Existing CSRF form field and server-side validation were preserved.

## Verification performed in this environment
- Python syntax compilation passed for app.py, ML modules, tests, and the training/evaluation scripts.
- Static inspection confirms the index form sends `csrf_token` and `/predict` rejects missing/mismatched tokens.

## Not verified here
Flask and Waitress are not installed in the current execution environment, so I could not run Flask test-client checks, launch Waitress, or verify a live CSRF rejection. Run the full tests after installing `requirements.txt`, then verify a POST without a CSRF token returns HTTP 400 and the normal form submission succeeds.

## Important deployment notes
- Keep the secret key out of source control and do not commit `.env`.
- Set `COOKIE_SECURE=1` only when HTTPS is actually configured; otherwise browser sessions over plain HTTP will not be sent.
- The rate limiter remains in-memory and is not shared across workers/instances. Use a shared rate-limit backend before multi-worker public deployment.
- This is an academic triage tool, not a guarantee of safe or malicious status.
