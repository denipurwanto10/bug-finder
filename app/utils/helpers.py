"""Generic helpers: masking, similarity, scoring, URL utils."""
from __future__ import annotations

import difflib
import re
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from app.config.settings import SEVERITY_WEIGHTS

_SENSITIVE_KEYS = {"password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
                   "access_token", "refresh_token", "sessionid", "session", "cookie",
                   "authorization", "private_key", "client_secret"}


def mask_secrets(text: str) -> str:
    out = str(text or "")
    # mask key=value pairs with sensitive keys
    def _sub(m):
        return m.group(1) + "***"
    out = re.sub(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|sessionid|cookie|authorization)(\s*[=:]\s*)([^\s&;,'\"\n\r]+)",
                 lambda m: m.group(1) + m.group(2) + "***", out)
    # mask long JWT-looking strings
    out = re.sub(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", "eyJ***.***.***", out)
    return out[:4000]


def response_similarity(a: str, b: str) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a[:6000], b[:6000]).ratio()


def compute_security_score(findings) -> int:
    penalty = 0
    for f in findings:
        sev = getattr(f, "severity", "Informational")
        if isinstance(f, dict):
            sev = f.get("severity", "Informational")
        penalty += SEVERITY_WEIGHTS.get(sev, 0)
    return max(0, 100 - penalty)


def severity_counts(findings) -> dict:
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev = f.severity if hasattr(f, "severity") else f.get("severity", "Informational")
        if sev in counts:
            counts[sev] += 1
    return counts


def set_query_param(url: str, param: str, value: str) -> str:
    parts = urlparse(url)
    q = dict(parse_qsl(parts.query, keep_blank_values=True))
    q[param] = value
    new_q = urlencode(q)
    return urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, new_q, parts.fragment))


def get_hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def is_valid_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.hostname)
    except Exception:
        return False


def truncate(text: str, limit: int = 1500) -> str:
    t = str(text or "")
    return t if len(t) <= limit else t[:limit] + f"... [truncated {len(t) - limit} chars]"


def arithmetic_canary() -> tuple[str, str]:
    """Return (expression, expected) for a math-eval probe, e.g. ('7*13', '91').

    Arithmetic output proves server-side evaluation: plain reflection of the
    expression is NOT counted as evidence — only the computed result.
    """
    import random
    a = random.randint(11, 89)
    b = random.randint(11, 89)
    return f"{a}*{b}", str(a * b)


def stable_response(body: str) -> str:
    """Normalize volatile content (timestamps, CSRF tokens, ads) for comparison."""
    import re
    t = body or ""
    t = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2})?", "[TS]", t)
    t = re.sub(r"\d{2}:\d{2}(:\d{2})?", "[TS]", t)
    t = re.sub(r'(?i)(csrf|nonce|token|session)[\"\']?\s*[:=]\s*[\"\']?[A-Za-z0-9+/=_-]{8,}[\"\']?', r"\1=[X]", t)
    t = re.sub(r"value=\"[A-Za-z0-9+/=_-]{16,}\"", 'value="[X]"', t)
    return t
