"""Dependency-light validation and risk-label helpers for the web app."""
from urllib.parse import urlsplit


def validate_url(raw):
    value = (raw or "").strip()
    if not value:
        return None, "Enter a URL to analyze."
    if len(value) > 2048:
        return None, "URL is too long (maximum 2,048 characters)."
    if any(ord(c) < 32 for c in value):
        return None, "URL contains control characters."
    candidate = value if "://" in value else "https://" + value
    try:
        parsed = urlsplit(candidate)
        _ = parsed.port  # triggers ValueError for invalid port strings
    except ValueError:
        return None, "The URL format is invalid. Check the hostname and port."
    if parsed.scheme.lower() not in {"http", "https"}:
        return None, "Only HTTP and HTTPS URLs are supported."
    if not parsed.hostname or "." not in parsed.hostname and parsed.hostname.lower() != "localhost":
        return None, "Enter a valid hostname, such as example.com."
    return candidate, None


def risk_level(score):
    if score >= 75:
        return "HIGH", "#ff4d4d"
    if score >= 30:
        return "MEDIUM", "#ffb347"
    return "LOW", "#32cd32"

