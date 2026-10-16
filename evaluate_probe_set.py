"""Evaluate the bundled model on the curated legitimate-only smoke-test CSV.
This is not a replacement for an independent Tranco + phishing-feed benchmark.
"""
import json
from pathlib import Path
import pandas as pd
from ml.brands import is_allowlisted, registrable_domain
from ml.model_service import PhishingModel
from ml.url_features import FEATURE_NAMES, extract_url_features, parse_url

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / "data" / "evaluation" / "curated_legitimate_probe.csv"


def main():
    if not INPUT.exists():
        raise SystemExit(f"Probe set not found: {INPUT}")
    df = pd.read_csv(INPUT)
    model = PhishingModel()
    X = pd.DataFrame([extract_url_features(u) for u in df["URL"]], columns=FEATURE_NAMES)
    probabilities = model.pipeline.predict_proba(X)[:, 1]
    threshold = float(model.metadata.get("threshold", 0.75))
    flagged = probabilities >= threshold
    hosts = df["URL"].map(lambda u: parse_url(u)[1].hostname or "")
    allow = hosts.map(is_allowlisted).to_numpy()
    flagged_after_allowlist = flagged & ~allow
    domains = df["URL"].map(lambda u: registrable_domain(parse_url(u)[1].hostname or ""))
    metrics = {
        "dataset": "Curated legitimate URL probe set (hand-assembled; not Tranco and not a representative benchmark)",
        "samples": int(len(df)), "threshold": threshold,
        "false_positives": int(flagged.sum()),
        "false_positive_rate": float(flagged.mean()),
        "false_positives_with_allowlist": int(flagged_after_allowlist.sum()),
        "false_positive_rate_with_allowlist": float(flagged_after_allowlist.mean()),
        "distinct_domains": int(domains.nunique()),
        "distinct_domains_flagged_model_only": int(domains[flagged].nunique()),
        "development_note": "This probe overlaps the development process (earlier thresholds were chosen while looking at it). Prefer reports/holdout_metrics.json, which is domain-disjoint and scored once.",
        "median_phishing_probability": float(pd.Series(probabilities).median()),
        "p95_phishing_probability": float(pd.Series(probabilities).quantile(0.95)),
        "note": "Legitimate-only development smoke test; it does not estimate phishing recall or overall real-world accuracy. Use Tranco plus an independently sourced phishing feed for a proper external benchmark.",
    }
    reports = ROOT / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "real_world_probe_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    out = df.copy()
    out["phishing_probability"] = probabilities
    out["flagged_phishing"] = flagged
    out.to_csv(reports / "real_world_probe_predictions.csv", index=False)
    print(json.dumps(metrics, indent=2))

if __name__ == "__main__":
    main()
