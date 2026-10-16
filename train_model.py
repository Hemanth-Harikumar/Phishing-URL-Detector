"""Train an URL-only phishing classifier from the UCI PhiUSIIL CSV dataset.

Expected columns: URL and label. PhiUSIIL convention: label 0=phishing, 1=legitimate.
Other datasets are accepted with labels {0,1} only when --label-map is explicitly documented.
"""
import argparse, json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from ml.brands import registrable_domain
from ml.url_features import FEATURE_NAMES, extract_url_features, parse_url

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "raw" / "PhiUSIIL_Phishing_URL_Dataset.csv"
MODEL_PATH = ROOT / "models" / "phishing_model.joblib"
HOLDOUT_PATH = ROOT / "data" / "evaluation" / "holdout_legitimate.csv"


def download_uci():
    try:
        from ucimlrepo import fetch_ucirepo
    except ImportError as exc:
        raise SystemExit("Install dependencies first: pip install -r requirements.txt") from exc
    print("Downloading PhiUSIIL from the UCI Machine Learning Repository...")
    ds = fetch_ucirepo(id=967)
    frame = pd.concat([ds.data.features, ds.data.targets], axis=1)
    if "URL" not in frame.columns or "label" not in frame.columns:
        raise SystemExit(f"Unexpected UCI columns: {list(frame.columns)}")
    DATA_PATH.parent.mkdir(parents=True, exist_ok=True)
    frame[["URL", "label"]].to_csv(DATA_PATH, index=False)
    print(f"Saved {len(frame):,} URL/label rows to {DATA_PATH}")


def domain_group(url):
    _, parsed = parse_url(str(url))
    return registrable_domain(parsed.hostname or "") or (parsed.hostname or "")


def pick_threshold(y_val, probs_val, target_fpr):
    """Lowest threshold whose validation false-positive rate is <= target (maximises recall)."""
    legit = probs_val[y_val == 0]
    for t in np.arange(0.30, 0.951, 0.01):
        if float((legit >= t).mean()) <= target_fpr:
            return round(float(t), 2)
    return 0.95


def confusion(y, probs, t):
    pred = (probs >= t).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"threshold": float(t), "accuracy": float(accuracy_score(y, pred)),
            "precision_phishing": float(precision_score(y, pred, zero_division=0)),
            "recall_phishing": float(recall_score(y, pred, zero_division=0)),
            "f1_phishing": float(f1_score(y, pred, zero_division=0)),
            "false_positive_rate_legitimate_flagged": float(fp / max(1, fp + tn)),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=DATA_PATH, help="CSV containing URL and label columns")
    parser.add_argument("--download-uci", action="store_true", help="Download UCI PhiUSIIL using ucimlrepo")
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--threshold", type=float, default=None, help="Fixed threshold. If omitted, it is chosen on a validation split (never on the test split or holdout)")
    parser.add_argument("--target-fpr", type=float, default=0.02, help="Max validation false-positive rate when choosing the threshold")
    parser.add_argument("--holdout", type=Path, default=HOLDOUT_PATH, help="Legitimate-only holdout CSV; its domains are removed from training and it is scored once at the end")
    parser.add_argument("--max-rows", type=int, default=100000, help="Maximum rows sampled for faster training; use 0 for all rows")
    parser.add_argument("--extra-legitimate", type=Path, default=None, help="Optional CSV with URL column; all rows are treated as curated legitimate examples")
    args = parser.parse_args()
    if args.download_uci:
        download_uci()
    if not args.data.exists():
        raise SystemExit(f"Dataset not found: {args.data}\nRun: python train_model.py --download-uci")
    df = pd.read_csv(args.data)
    url_col = next((c for c in df.columns if c.lower() in {"url", "uri"}), None)
    label_col = next((c for c in df.columns if c.lower() in {"label", "result", "phishing", "target", "class"}), None)
    if not url_col or not label_col:
        raise SystemExit("CSV must contain a URL column and a binary label column (for PhiUSIIL: URL,label).")
    df = df[[url_col, label_col]].dropna().copy()
    df[url_col] = df[url_col].astype(str).str.strip()
    df = df[df[url_col].str.len() > 0].drop_duplicates(subset=[url_col])
    curated_urls = set()
    if args.extra_legitimate:
        if not args.extra_legitimate.exists():
            raise SystemExit(f"Extra legitimate CSV not found: {args.extra_legitimate}")
        extra = pd.read_csv(args.extra_legitimate)
        extra_url_col = next((c for c in extra.columns if c.lower() in {"url", "uri"}), None)
        if not extra_url_col:
            raise SystemExit("Extra legitimate CSV must contain a URL column.")
        extra = extra[[extra_url_col]].dropna().copy()
        extra.columns = [url_col]
        extra[url_col] = extra[url_col].astype(str).str.strip()
        extra = extra[extra[url_col].str.len() > 0]
        curated_urls = set(extra[url_col].astype(str))
        # PhiUSIIL convention: label 1 means legitimate.
        extra[label_col] = 1
        df = pd.concat([df, extra], ignore_index=True).drop_duplicates(subset=[url_col])
        print(f"Added {len(extra):,} curated legitimate URL examples from {args.extra_legitimate}")
    holdout_domains = set()
    if args.holdout and Path(args.holdout).exists():
        hold = pd.read_csv(args.holdout)
        holdout_domains = set(hold["URL"].astype(str).map(domain_group))
        before = len(df)
        df = df[~df[url_col].map(domain_group).isin(holdout_domains)]
        print(f"Removed {before - len(df):,} training rows whose domain is in the holdout set ({len(holdout_domains)} domains)")
    labels = pd.to_numeric(df[label_col], errors="coerce")
    valid = labels.isin([0, 1])
    df, labels = df.loc[valid].copy(), labels.loc[valid].astype(int)
    if labels.nunique() != 2:
        raise SystemExit("Need both binary classes 0 and 1 in the label column.")
    # PhiUSIIL: 0 phishing, 1 legitimate. Convert to positive class = phishing.
    # For generic datasets this convention must be changed in this block if labels differ.
    y = (labels == 0).astype(int).to_numpy()
    source_rows = len(df)
    if args.max_rows and len(df) > args.max_rows:
        # Keep every curated legitimate example; sample only the large source dataset.
        working = df.copy()
        working["_model_label"] = y
        working["_is_curated"] = working[url_col].astype(str).isin(curated_urls)
        curated_part = working[working["_is_curated"]]
        source_part = working[~working["_is_curated"]]
        # Stratified sample keeps both source labels represented; fixed seed is reproducible.
        sampled_parts = []
        for cls, part in source_part.groupby("_model_label"):
            n_cls = max(1, round(args.max_rows * len(part) / len(source_part)))
            sampled_parts.append(part.sample(n=min(n_cls, len(part)), random_state=42))
        sampled = pd.concat(sampled_parts + [curated_part]).sample(frac=1, random_state=42)
        df = sampled[[url_col]].reset_index(drop=True)
        y = sampled["_model_label"].astype(int).to_numpy()
    print(f"Source rows after cleaning: {source_rows:,}; training sample: {len(df):,}; phishing={int(y.sum()):,}; legitimate={int((y==0).sum()):,}")
    print("Extracting URL-only features (this may take a few minutes)...")
    X = pd.DataFrame([extract_url_features(u) for u in df[url_col]], columns=FEATURE_NAMES)
    groups = df[url_col].map(domain_group).to_numpy()
    # Three-way domain-grouped split: train / validation (threshold choice) / test (reported once).
    outer = GroupShuffleSplit(n_splits=1, test_size=args.test_size, random_state=42)
    trainval_idx, test_idx = next(outer.split(X, y, groups=groups))
    inner = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=7)
    tr_rel, va_rel = next(inner.split(X.iloc[trainval_idx], y[trainval_idx], groups=groups[trainval_idx]))
    train_idx, val_idx = trainval_idx[tr_rel], trainval_idx[va_rel]
    for name, idx in (("train", train_idx), ("validation", val_idx), ("test", test_idx)):
        if len(np.unique(y[idx])) < 2:
            raise SystemExit(f"The {name} split lacks one class; provide more data.")
    assert not (set(groups[train_idx]) & set(groups[test_idx])) and not (set(groups[val_idx]) & set(groups[test_idx]))
    model = Pipeline([("imputer", SimpleImputer(strategy="median")), ("model", RandomForestClassifier(
        n_estimators=180, min_samples_leaf=2, class_weight="balanced_subsample", n_jobs=-1, random_state=42
    ))])
    model.fit(X.iloc[train_idx], y[train_idx])
    probs_val = model.predict_proba(X.iloc[val_idx])[:, 1]
    if args.threshold is None:
        threshold = pick_threshold(y[val_idx], probs_val, args.target_fpr)
        selection_note = f"Chosen on the validation split: lowest threshold with validation FPR <= {args.target_fpr:.0%}. The test split and holdout were not used."
    else:
        threshold = float(args.threshold)
        selection_note = "Fixed by --threshold; not tuned on any split."
    probs = model.predict_proba(X.iloc[test_idx])[:, 1]
    y_test = y[test_idx]
    at_t = confusion(y_test, probs, threshold)
    metrics = {
        "source_rows": int(source_rows), "rows_used": int(len(df)), "train_rows": int(len(train_idx)),
        "validation_rows": int(len(val_idx)), "test_rows": int(len(test_idx)),
        "split_method": "three-way domain-group split (registrable-domain grouping, small built-in suffix list)",
        "threshold": threshold, "threshold_selection_note": selection_note, "target_validation_fpr": args.target_fpr,
        **{k: v for k, v in at_t.items() if k != "threshold"},
        "roc_auc": float(roc_auc_score(y_test, probs)),
        "validation_at_threshold": confusion(y[val_idx], probs_val, threshold),
        "metrics_at_threshold_0_5": confusion(y_test, probs, 0.5),
        "feature_names": FEATURE_NAMES, "label_definition": "1=phishing, 0=legitimate",
        "dataset_label_mapping": "PhiUSIIL label 0=phishing, label 1=legitimate",
    }
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": model, "metadata": metrics}, MODEL_PATH)
    reports_dir = ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "training_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    if args.holdout and Path(args.holdout).exists():
        hold = pd.read_csv(args.holdout)
        Xh = pd.DataFrame([extract_url_features(u) for u in hold["URL"]], columns=FEATURE_NAMES)
        ph = model.predict_proba(Xh)[:, 1]
        hm = {"dataset": "holdout_legitimate.csv (hand-assembled, legitimate-only, domains removed from training; scored once)",
              "samples": int(len(hold)), "domains": int(hold["URL"].map(domain_group).nunique()), "threshold": threshold,
              "false_positives": int((ph >= threshold).sum()), "false_positive_rate": float((ph >= threshold).mean()),
              "needs_review_rate": float(((ph >= 0.30) & (ph < threshold)).mean()),
              "median_phishing_probability": float(np.median(ph)),
              "note": "Legitimate-only: says nothing about phishing recall."}
        (reports_dir / "holdout_metrics.json").write_text(json.dumps(hm, indent=2), encoding="utf-8")
        print("\nHoldout (legitimate-only):", json.dumps(hm, indent=2))
    print("\nEvaluation on held-out test set:")
    print(json.dumps({k: v for k, v in metrics.items() if k != "feature_names"}, indent=2))
    print(f"\nSaved model: {MODEL_PATH}")

if __name__ == "__main__":
    main()
