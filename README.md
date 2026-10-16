# Phishing URL Detector

A Flask-based web application that analyzes URLs using a hostname-based Random Forest classifier, explains phishing risk scores, and maintains a scan history using SQLite.

This project is an **academic phishing triage tool**. It analyzes URL and hostname characteristics without fetching the target website, inspecting page content, or performing live network lookups.

## Features

- **Machine-learning-based risk assessment:** Produces a phishing probability score and classifies URLs according to a configurable threshold.
- **Brand impersonation detection:** Identifies suspicious brand names in subdomains, unrelated registrable domains, and look-alike spellings. Examples include `paypal.com.secure-login.tk`, `secure-chase-banking.com`, `paypa1`, `amaz0n`, and `micros0ft`.
- **Domain allowlist:** Recognizes selected well-known brand domains using exact registrable-domain matching. The allowlist is not applied to user-content hosting services such as `sites.google.com`, SharePoint subdomains, and `github.io`.
- **Hostname-focused features:** Uses 23 hostname-focused features designed to remain invariant to URL scheme and `www` prefixes.
- **Prediction explanations:** Uses SHAP when supported, with a feature-importance fallback.
- **Scan history:** Stores scan results in SQLite and provides a history interface.
- **Optional AI-generated reports:** Supports an optional OpenAI-compatible LLM integration. Without an API key, the application provides a local evidence-based report.
- **Security hardening:** Implements CSRF protection, request-size limits, security headers, session-cookie settings, and basic in-process rate limiting.
- **Automated tests:** Includes tests for URL validation, feature extraction, brand impersonation, allowlist behavior, and model-service functionality.

## Technology Stack

- Python
- Flask
- Scikit-learn
- Pandas and NumPy
- Joblib
- SQLite
- HTML and CSS
- Optional SHAP explanations
- Optional OpenAI-compatible API integration
- Waitress for production WSGI serving

## Model Evaluation

The following results were reported for the held-out test split, grouped by registrable domain. The classification threshold of `0.71` was selected using the validation split with a target false-positive rate of at most 2%.

| Metric | Threshold 0.71 | Threshold 0.50 |
|---|---:|---:|
| Accuracy | 82.2% | 81.0% |
| Precision (phishing) | 95.6% | 83.2% |
| Recall (phishing) | 55.7% | 62.7% |
| False-positive rate | 1.6% | 7.7% |
| ROC-AUC | 0.823 | — |

The higher threshold improves precision and reduces false positives, but it also misses more phishing URLs.

### Legitimate-Only Evaluation

These checks measure false positives on legitimate URLs. They do not measure phishing recall.

| Evaluation set | URLs / domains | False positives before allowlist | After allowlist |
|---|---|---|---|
| Clean holdout, domain-disjoint and scored once | 146 URLs / 73 domains | 3 (2.1%) | Not reported |
| Development probe, overlapping development data | 280 URLs / 35 domains | 40 (14.3%), across 14 domains | 28 (10.0%) |

The clean holdout is a small, hand-assembled dataset whose domains were removed from training and which was scored once. The development probe overlaps the development process and should not be treated as an independent benchmark.

## Limitations

- **Limited phishing recall:** Recall at threshold `0.71` is approximately 56% on the reported test split. Hostname-only features cannot identify every phishing URL, particularly when malicious hosts have ordinary-looking names.
- **No independent phishing benchmark yet:** The test split comes from the same underlying dataset used for training. Independent evaluation using a current legitimate-domain list and a separately sourced phishing feed is still needed.
- **Small, hand-assembled legitimate sets:** The clean holdout and development probe produce different false-positive rates. Their results should be interpreted cautiously.
- **Incomplete domain handling:** Registrable-domain extraction uses a small built-in suffix list rather than the full Public Suffix List.
- **Incomplete brand coverage:** The brand list and allowlist are manually maintained and cannot cover every brand or impersonation pattern.
- **Possible look-alike false positives:** Similarity matching can flag legitimate words that resemble short brand names. These signals contribute to the model rather than acting as definitive rules.
- **Dataset artifacts:** The PhiUSIIL dataset contains artifacts that can inflate performance if exploited. Earlier versions achieved misleadingly high scores of 99.6%; those results should not be interpreted as real-world accuracy.
- **No page-content analysis:** The application does not inspect website content, certificates, redirects, or live reputation feeds.

The application should not be considered a complete phishing detector or a security guarantee. Do not use its output as the sole basis for blocking URLs or responding to security incidents.

## Requirements

- Python 3.11 or 3.12 recommended
- pip
- Internet access for downloading the training dataset
- A compatible environment for the Python dependencies

## Installation and Quick Start

The trained model is **not included in this repository**. You must generate it before starting the application.

### 1. Clone the repository

```powershell
git clone https://github.com/Hemanth-Harikumar/Phishing-URL-Detector.git
cd Phishing-URL-Detector
```

### 2. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run the following command in the current terminal and try activating again:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Generate the trained model

Download the PhiUSIIL dataset through the UCI Machine Learning Repository integration and train the classifier:

```powershell
python train_model.py --download-uci
```

To include the project's curated legitimate URL examples during training, run:

```powershell
python train_model.py --extra-legitimate data/evaluation/curated_legitimate_training.csv
```

The training process generates:

- `models/phishing_model.joblib`
- `reports/training_metrics.json`
- `reports/holdout_metrics.json`

The raw PhiUSIIL CSV is not bundled in the repository. The dataset download requires network access and the `ucimlrepo` dependency specified by the project.

### 5. Start the application

After the model has been generated successfully, run:

```powershell
python app.py
```

Open the application in your browser:

`http://127.0.0.1:5000`

The application creates or uses its SQLite database for scan history.

## Retraining Options

The training script supports additional options for evaluation and threshold selection.

| Option | Purpose |
|---|---|
| `--download-uci` | Download the PhiUSIIL dataset through `ucimlrepo` |
| `--data PATH` | Specify a local CSV containing URL and label columns |
| `--threshold VALUE` | Set a fixed classification threshold |
| `--target-fpr VALUE` | Set the target validation false-positive rate |
| `--max-rows NUMBER` | Limit the number of source rows used for training; default is 100,000 |
| `--max-rows 0` | Use all available source rows |
| `--extra-legitimate PATH` | Include curated legitimate URLs in training |
| `--holdout PATH` | Specify the legitimate-only holdout CSV |

By default, the threshold is selected using the validation split with a target false-positive rate of 2%. The test split and clean holdout are not used to select the threshold.

To evaluate the development probe after training, run:

```powershell
python evaluate_probe_set.py
```

Review the generated reports carefully. The development probe overlaps the development process and is not an independent benchmark.

## Optional AI-Generated Security Reports

The application can optionally use an OpenAI-compatible API to generate security reports.

1. Copy `.env.example` to `.env`.
2. Set `OPENAI_API_KEY` to your own API key if you want to enable the integration.
3. Configure `OPENAI_MODEL` as needed.
4. Set a suitable `FLASK_SECRET_KEY` for your environment.

Keep `.env` private and never commit it to Git.

Without an API key, the application uses its local evidence-based reporting functionality. The URL is treated as untrusted input, and the LLM does not determine or override the model's verdict.

## Architecture

1. **`app.py`** validates input URLs and handles web requests without fetching the target website.
2. **`ml/url_features.py`** extracts 23 hostname-focused features.
3. **`ml/brands.py`** implements brand-impersonation signals, registrable-domain handling, and the domain allowlist.
4. **`ml/model_service.py`** loads the trained Random Forest model, generates predictions, applies the configured threshold, and handles allowlist overrides.
5. **SHAP or feature importance** provides prediction explanations, depending on availability and compatibility.
6. **`ml/reporting.py`** generates local or optional LLM-assisted reports.
7. **SQLite** stores scan history for later review.

The allowlist can override the final verdict for selected domains, while the raw model score remains visible. User-content hosting domains are excluded from this allowlist override.

## Testing

Run the automated test suite:

```powershell
python -m unittest discover -s tests -v
```

The current local verification run passed **28 tests** covering:

- URL validation and risk-label boundaries
- Hostname feature extraction and schema consistency
- Brand impersonation and look-alike detection
- Registrable-domain and allowlist behavior
- User-content host handling
- Model prediction shape and probability output
- Scheme and `www` invariance
- Application helper functions

These unit tests verify implemented behavior but do not establish production readiness or guarantee real-world detection accuracy.

## Dataset Attribution

This project uses the PhiUSIIL Phishing URL (Website) Dataset.

Prasad, A. & Chandra, S. (2024). *PhiUSIIL: Phishing URL (Website) Dataset*. UCI Machine Learning Repository.

https://doi.org/10.1016/j.cose.2023.103545

Dataset license: Creative Commons Attribution 4.0 International (CC BY 4.0). See [`LICENSE-DATASET.txt`](LICENSE-DATASET.txt) for attribution and licensing information.

## Security and Production Configuration

The Flask development server is intended for local development only.

For a production deployment:

- Set `APP_ENV=production`.
- Configure a persistent, randomly generated `FLASK_SECRET_KEY` of at least 32 characters.
- Serve the application through HTTPS and set `COOKIE_SECURE=1`.
- Use the production WSGI server configuration provided by the application, including Waitress where applicable.
- Keep API keys and secret values out of version control.
- Replace the in-process rate limiter with shared storage, such as Redis, when deploying multiple workers or instances.
- Configure trusted proxy handling deliberately; do not trust arbitrary forwarded client-IP headers.

Generate a secret key with:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Set the generated value securely in your deployment environment. Do not paste it into source code or commit it to Git.

For local HTTP testing, leave `COOKIE_SECURE` unset or set it to `0`. Use `COOKIE_SECURE=1` only when the application is accessed through HTTPS.

The application implements CSRF protection, baseline security headers, HTTP-only and SameSite session-cookie settings, configurable Secure cookies, request-size limits, and basic in-process rate limiting. These safeguards do not by themselves make an application production-ready.

## Responsible Use

This project is intended for academic demonstration, learning, and preliminary phishing-risk triage. It has known limitations and has not been independently validated against a current, representative phishing benchmark.

Do not treat a low risk score as proof that a URL is safe. Use additional security controls and independent threat-intelligence sources when making consequential decisions.
