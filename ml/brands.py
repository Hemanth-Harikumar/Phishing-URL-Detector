"""Brand-impersonation signals and a small allowlist of well-known domains.

Everything here is hostname-based and has no network access. The brand list is
deliberately small and hand-maintained; it is NOT a reputation database.
"""
from functools import lru_cache

# Multi-label public suffixes we recognise. This is a small subset of the real
# Public Suffix List, enough for the brands below.
MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in",
    "net.in", "org.in", "ac.in", "gov.in", "co.nz", "co.jp", "com.br", "com.cn",
    "com.mx", "co.za", "com.sg", "com.hk", "com.tr", "com.ar", "co.kr", "com.pk",
    "com.bd", "com.my", "com.ph", "com.vn", "com.ng", "com.eg", "com.sa", "co.id", "co.th",
}

# brand token -> legitimate registrable domains
BRAND_DOMAINS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "gstatic.com", "google.co.in", "google.co.uk"},
    "microsoft": {"microsoft.com", "microsoftonline.com", "live.com", "office.com", "office365.com",
                  "outlook.com", "windows.com", "azure.com", "bing.com", "msn.com", "skype.com", "xbox.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.co.jp",
               "amazon.com.au", "amazon.fr", "amazon.es", "amazon.it"},
    "facebook": {"facebook.com", "fb.com", "messenger.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"},
    "twitter": {"twitter.com", "x.com", "t.co"},
    "github": {"github.com"},
    "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "metamask": {"metamask.io"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "ebay": {"ebay.com", "ebay.co.uk", "ebay.in"},
    "yahoo": {"yahoo.com"},
    "spotify": {"spotify.com"},
    "telegram": {"telegram.org", "t.me"},
    "discord": {"discord.com", "discord.gg"},
    "zoom": {"zoom.us"},
    "fedex": {"fedex.com"},
    "dhl": {"dhl.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "citibank": {"citibank.com", "citi.com"},
    "americanexpress": {"americanexpress.com", "aexp.com"},
    "capitalone": {"capitalone.com"},
    "hsbc": {"hsbc.com", "hsbc.co.uk", "hsbc.co.in"},
    "barclays": {"barclays.co.uk", "barclays.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "onlinesbi": {"onlinesbi.sbi", "sbi.co.in", "sbicard.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"},
}

# Hosts on these suffixes let anyone publish content, so a "known brand domain"
# match must NOT earn an allowlist pass (phishing is routinely hosted there).
USER_CONTENT_SUFFIXES = (
    "sites.google.com", "docs.google.com", "forms.google.com", "drive.google.com",
    "storage.googleapis.com", "googleusercontent.com", "firebaseapp.com", "web.app",
    "sharepoint.com", "onedrive.live.com", "forms.office.com", "github.io",
    "githubusercontent.com", "blogspot.com", "amazonaws.com", "azurewebsites.net",
    "pages.dev", "netlify.app", "herokuapp.com", "weebly.com", "wixsite.com",
    "t.me", "discord.gg", "forms.gle", "goo.gl", "t.co", "bit.ly",
)

ALLOWLIST = frozenset(d for domains in BRAND_DOMAINS.values() for d in domains)

_LEET = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
NO_MATCH_DISTANCE = 3.0


def clean_host(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    return host[4:] if host.startswith("www.") else host


def registrable_domain(host: str) -> str:
    labels = [p for p in clean_host(host).split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _main_label(host: str) -> str:
    reg = registrable_domain(host).split(".")
    return reg[0] if reg else ""


def is_user_content_host(host: str) -> bool:
    host = clean_host(host)
    return any(host == s or host.endswith("." + s) for s in USER_CONTENT_SUFFIXES)


def is_allowlisted(host: str) -> bool:
    """True for a well-known brand domain that is not a user-content host."""
    host = clean_host(host)
    return bool(host) and registrable_domain(host) in ALLOWLIST and not is_user_content_host(host)


def _variants(token: str) -> set:
    base = token.translate(_LEET).replace("rn", "m").replace("vv", "w")
    return {base.replace("1", "l"), base.replace("1", "i")}


def _lev(a: str, b: str, max_d: int) -> int:
    if abs(len(a) - len(b)) > max_d:
        return max_d + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        if min(cur) > max_d:
            return max_d + 1
        prev = cur
    return prev[-1]


def _contains_brand(token: str, brand: str) -> bool:
    # Short brands need an exact token match to avoid hits like "pineapple".
    return brand in token if len(brand) >= 6 else token == brand


@lru_cache(maxsize=200_000)
def _closest_brand(token: str):
    """Return (distance, brand) for the nearest brand within tolerance, else (3, '')."""
    best = (NO_MATCH_DISTANCE, "")
    if len(token) < 4:
        return best
    for brand in BRAND_DOMAINS:
        if len(brand) < 5:
            continue
        limit = 2 if len(brand) >= 8 else 1
        for variant in _variants(token) | {token}:
            d = _lev(variant, brand, limit)
            if d <= limit and d < best[0]:
                best = (float(d), brand)
    return best


def brand_signals(host: str) -> dict:
    """Hostname-only impersonation features plus a human-readable detail."""
    host = clean_host(host)
    out = {"brand_in_subdomain": 0.0, "brand_in_registrable": 0.0,
           "brand_lookalike": 0.0, "brand_min_edit_distance": NO_MATCH_DISTANCE, "detail": ""}
    labels = [p for p in host.split(".") if p]
    if len(labels) < 2 or host.replace(".", "").isdigit():
        return out
    reg = registrable_domain(host)
    reg_labels = reg.split(".")
    sub_labels = labels[: len(labels) - len(reg_labels)]
    main = reg_labels[0]
    main_tokens = [t for t in {main, *main.split("-")} if t]
    sub_tokens = [t for lab in sub_labels for t in lab.split("-") if t]
    for brand, domains in BRAND_DOMAINS.items():
        if reg in domains:
            continue  # this really is the brand's domain
        if any(_contains_brand(t, brand) for t in sub_tokens):
            out["brand_in_subdomain"] = 1.0
            out["detail"] = out["detail"] or f"brand '{brand}' appears in a subdomain of {reg}"
        if any(_contains_brand(t, brand) for t in main_tokens):
            out["brand_in_registrable"] = 1.0
            out["detail"] = out["detail"] or f"brand '{brand}' appears in unrelated domain {reg}"
    for token in main_tokens:
        dist, brand = _closest_brand(token)
        if brand and reg not in BRAND_DOMAINS[brand]:
            out["brand_min_edit_distance"] = min(out["brand_min_edit_distance"], dist)
            exact_token = token == brand
            if not exact_token:
                out["brand_lookalike"] = 1.0
                out["detail"] = out["detail"] or f"'{token}' looks like brand '{brand}'"
    return out
