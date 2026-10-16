"""Scheme-invariant, hostname-focused URL feature extraction.

The model intentionally avoids raw URL length/path length as primary signals,
which can cause legitimate pages to look malicious. Scheme and leading www are
normalized away because they were collection artifacts in the source dataset.
"""
import ipaddress
import math
from collections import Counter
from urllib.parse import urlsplit

from .brands import brand_signals

FEATURE_NAMES = [
    "hostname_length", "hostname_label_count", "dot_count", "hostname_hyphen_count",
    "hostname_digit_count", "hostname_digit_ratio", "hostname_entropy",
    "at_count", "percent_count", "hostname_is_ip", "punycode_hostname",
    "subdomain_count", "has_port", "tld_length", "suspicious_tld",
    "suspicious_hostname_keyword_count", "hostname_underscore_count",
    "query_param_count", "has_fragment",
    "brand_in_subdomain", "brand_in_registrable", "brand_lookalike", "brand_min_edit_distance",
]
SUSPICIOUS_TLDS = {"zip", "mov", "click", "country", "gq", "tk", "ml", "cf", "ga", "work", "support", "top", "xyz", "rest", "fit"}
SUSPICIOUS_HOST_WORDS = {
    "login", "verify", "secure", "update", "account", "banking", "password",
    "signin", "wallet", "confirm", "webscr", "recover", "reset", "credential",
}


def suspicious_host_words(hostname: str) -> list[str]:
    """Return suspicious keywords found in a normalized hostname.

    Only the exact leading ``www.`` prefix is removed; ``str.lstrip`` is not
    appropriate here because it treats its argument as a set of characters.
    """
    host = (hostname or "").strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return sorted(word for word in SUSPICIOUS_HOST_WORDS if word in host)


def parse_url(url: str):
    value = (url or "").strip()
    candidate = value if "://" in value else "//" + value
    try:
        parsed = urlsplit(candidate)
    except ValueError:
        parsed = urlsplit("//invalid.local")
    return value, parsed


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in counts.values())


def extract_url_features(url: str) -> dict[str, float]:
    value, parsed = parse_url(url)
    host = (parsed.hostname or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    labels = [part for part in host.split(".") if part]
    tld = labels[-1] if labels else ""
    host_digits = sum(c.isdigit() for c in host)
    try:
        is_ip = int(bool(host) and _is_ip(host))
    except ValueError:
        is_ip = 0
    try:
        has_port = int(parsed.port is not None)
    except ValueError:
        has_port = 0
    # Hostname-only lexical signals; avoid counting a legitimate long path as a malicious hostname.
    label_words = set()
    for label in labels[:-1]:
        label_words.update(part for part in label.replace("-", ".").split(".") if part)
    query = parsed.query or ""
    query_params = len([part for part in query.split("&") if part]) if query else 0
    result = {
        "hostname_length": len(host),
        "hostname_label_count": len(labels),
        "dot_count": host.count("."),
        "hostname_hyphen_count": host.count("-"),
        "hostname_digit_count": host_digits,
        "hostname_digit_ratio": host_digits / max(1, len(host)),
        "hostname_entropy": _entropy(host),
        "at_count": value.count("@"),
        "percent_count": value.count("%"),
        "hostname_is_ip": is_ip,
        "punycode_hostname": int("xn--" in host),
        "subdomain_count": max(0, len(labels) - 2) if host and not is_ip else 0,
        "has_port": has_port,
        "tld_length": len(tld),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "suspicious_hostname_keyword_count": sum(word in label_words for word in SUSPICIOUS_HOST_WORDS),
        "hostname_underscore_count": host.count("_"),
        "query_param_count": query_params,
        "has_fragment": int(bool(parsed.fragment)),
    }
    if is_ip:
        result.update({"brand_in_subdomain": 0, "brand_in_registrable": 0,
                       "brand_lookalike": 0, "brand_min_edit_distance": 3})
    else:
        signals = brand_signals(host)
        result.update({k: signals[k] for k in ("brand_in_subdomain", "brand_in_registrable",
                                                "brand_lookalike", "brand_min_edit_distance")})
    return {name: float(result[name]) for name in FEATURE_NAMES}


def _is_ip(host: str) -> bool:
    ipaddress.ip_address(host)
    return True


def feature_vector(url: str) -> list[float]:
    values = extract_url_features(url)
    return [values[name] for name in FEATURE_NAMES]
