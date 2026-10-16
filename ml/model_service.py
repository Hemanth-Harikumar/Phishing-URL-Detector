"""Load the trained model and provide ML predictions + SHAP explanations.

Environment variables
---------------------
MODEL_THRESHOLD
    Override the classification threshold stored in the model bundle.
    Values between 0.30 and 0.95 are accepted; values outside that range
    are silently clamped.  Lower values (e.g. 0.60) increase recall at the
    cost of more false positives; higher values reduce false positives but
    miss more phishing URLs.  The model was trained with a default of 0.71
    (≤ 2% FPR on the validation split).

    Example .env entry::

        MODEL_THRESHOLD=0.60
"""
import os
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
from urllib.parse import urlsplit
from .brands import brand_signals, is_allowlisted, registrable_domain, clean_host
from .url_features import FEATURE_NAMES, extract_url_features, parse_url

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "phishing_model.joblib"

# Optional env-var override for the classification threshold.
def _resolve_threshold_override() -> float | None:
    raw = os.getenv("MODEL_THRESHOLD", "").strip()
    if not raw:
        return None
    try:
        val = float(raw)
        clamped = max(0.30, min(0.95, val))
        if clamped != val:
            import warnings
            warnings.warn(
                f"MODEL_THRESHOLD={val} is outside [0.30, 0.95]; clamped to {clamped}.",
                stacklevel=2,
            )
        return clamped
    except ValueError:
        import warnings
        warnings.warn(f"MODEL_THRESHOLD={raw!r} is not a valid float; ignoring.", stacklevel=2)
        return None

_THRESHOLD_OVERRIDE: float | None = _resolve_threshold_override()


class ModelNotReadyError(RuntimeError):
    pass

class PhishingModel:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = Path(model_path)
        self.pipeline = None
        self.metadata = {}
        self._explainer = None
        self.load()

    def load(self):
        if not self.model_path.exists():
            raise ModelNotReadyError(
                f"Model not found at {self.model_path}. Run `python train_model.py --download-uci` first."
            )
        bundle = joblib.load(self.model_path)
        self.pipeline = bundle["pipeline"]
        self.metadata = bundle.get("metadata", {})
        if self.metadata.get("feature_names") != FEATURE_NAMES:
            raise ModelNotReadyError("Model feature schema does not match the current feature extractor. Retrain the model.")

    def predict(self, url: str):
        row = pd.DataFrame([extract_url_features(url)], columns=FEATURE_NAMES)
        probability = float(self.pipeline.predict_proba(row)[0][1])
        # Prefer the env-var override, then the model's stored threshold, then a safe default.
        threshold = _THRESHOLD_OVERRIDE if _THRESHOLD_OVERRIDE is not None else float(self.metadata.get("threshold", 0.75))
        host = clean_host(parse_url(url)[1].hostname or "")
        known_domain = is_allowlisted(host)
        prediction = int(probability >= threshold) and not known_domain
        # The middle band is intentionally uncertain: URL-only models should not overclaim safety.
        needs_review = (not prediction) and (not known_domain) and probability >= 0.30
        signals = brand_signals(host)
        return {
            "is_phishing": bool(prediction),
            "needs_review": bool(needs_review),
            "known_domain": bool(known_domain),
            "registrable_domain": registrable_domain(host),
            "brand_detail": signals["detail"],
            "phishing_probability": probability,
            "risk_score": int(round(probability * 100)),
            "decision_threshold": threshold,
            "features": row.iloc[0].to_dict(),
        }


    def explain(self, url: str, top_n=6):
        """Return top SHAP feature contributions when SHAP is installed and compatible."""
        row = pd.DataFrame([extract_url_features(url)], columns=FEATURE_NAMES)
        try:
            import shap
            if self._explainer is None:
                estimator = self.pipeline.named_steps.get("model", self.pipeline)
                self._explainer = shap.TreeExplainer(estimator)
            values = self._explainer.shap_values(row)
            # Binary classifiers may return list[class] or an ndarray depending on SHAP version.
            if isinstance(values, list):
                contributions = np.asarray(values[1])[0]
            else:
                arr = np.asarray(values)
                if arr.ndim == 3:
                    contributions = arr[0, :, 1] if arr.shape[-1] == 2 else arr[0, :, 0]
                elif arr.ndim == 2:
                    contributions = arr[0]
                else:
                    contributions = arr.reshape(-1)
            items = []
            for name, value in zip(FEATURE_NAMES, contributions):
                items.append({"feature": name, "value": float(row.iloc[0][name]), "impact": float(value),
                              "direction": "increases phishing score" if value > 0 else "decreases phishing score"})
            return sorted(items, key=lambda x: abs(x["impact"]), reverse=True)[:top_n], "SHAP"
        except Exception:
            # Transparent fallback: model feature importances, not falsely labelled as SHAP.
            estimator = self.pipeline.named_steps.get("model", self.pipeline)
            importances = getattr(estimator, "feature_importances_", None)
            if importances is None:
                return [], "Unavailable"
            items = [{"feature": name, "value": float(row.iloc[0][name]), "impact": float(importance),
                      "direction": "model importance (direction unavailable)"}
                     for name, importance in zip(FEATURE_NAMES, importances)]
            return sorted(items, key=lambda x: x["impact"], reverse=True)[:top_n], "Feature importance fallback"
