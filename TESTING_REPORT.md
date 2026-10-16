# Phishing URL Detector v5.1 — Test Report

Date: 2026-10-16

## Changes made

1. Fixed suspicious hostname keyword normalization. The previous use of `lstrip("www.")` removed any leading combination of the characters `w` and `.` instead of removing only the exact `www.` prefix. The app now uses a dedicated helper that removes only `www.` and checks suspicious hostname words consistently.
2. Moved URL validation and risk-label helpers to `ml/web_helpers.py`. This isolates pure helper logic from the Flask runtime and allows these functions to be unit-tested independently.
3. Added regression tests covering `wallet.com`, `www.wallet.com`, case normalization and exact prefix handling.
4. Updated the README with the maintenance changes and test instructions.

## Automated results

- `python -m compileall -q app.py ml tests train_model.py evaluate_probe_set.py`: PASS
- `python -m pytest -q`: PASS — 28 tests passed
- Bundled model load: PASS
- Feature schema: PASS — 23 features returned
- Prediction smoke test for `google.com`: PASS — allowlist override applied
- Prediction smoke test for `paypal.com.secure-login.tk`: PASS — high phishing score and phishing classification
- SHAP explanation smoke test: PASS — six explanation entries returned
- Regression check for suspicious word `wallet`: PASS

## Limitations of this review

The review environment does not have Flask installed, and outbound package installation is unavailable. Therefore the full Flask server, browser workflow, POST request flow, SQLite history workflow and deployment configuration were not executed end-to-end. The 28 passing tests cover the dependency-light helpers, feature extraction, brand logic and model service; they should not be interpreted as proof that the entire web application has been browser-tested.

Install dependencies in a suitable Python environment and run `python -m pytest -q`, then start the server and manually test scan submission, result rendering, report output, history persistence and invalid-input handling before public deployment.

## Known pre-deployment work

- Add and test CSRF protection.
- Configure a persistent strong `FLASK_SECRET_KEY` through environment variables.
- Use a production WSGI server rather than Flask's development server.
- Review the in-memory rate limiter for multi-worker deployment.
- Perform browser-based end-to-end and security tests.

## Verdict

The identified hostname-processing bug is fixed and the tests that can run in this environment pass. This is a tested maintenance build, but end-to-end web verification and deployment hardening remain outstanding.
