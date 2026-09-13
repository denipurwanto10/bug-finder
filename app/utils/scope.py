"""Scope enforcement: block any request whose host is outside the allowed scope."""
from __future__ import annotations

from urllib.parse import urlparse


def normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def host_in_scope(host: str, scope: list[str]) -> bool:
    """Allow exact match or subdomain match. Scope entries may be hostnames or IPs."""
    host = normalize_host(host)
    if not host:
        return False
    for entry in scope:
        e = normalize_host(entry)
        if not e:
            continue
        if e.startswith("*."):
            e = e[2:]
        if host == e or host.endswith("." + e):
            return True
    return False


def url_in_scope(url: str, scope: list[str]) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except Exception:
        return False
    return host_in_scope(host, scope)


class ScopeGuard:
    def __init__(self, scope: list[str]):
        self.scope = [normalize_host(s).lstrip("*.") for s in (scope or []) if s and s.strip()]

    def allowed(self, url: str) -> bool:
        return url_in_scope(url, self.scope)

    def check(self, url: str) -> None:
        if not self.allowed(url):
            raise ScopeViolation(f"Blocked out-of-scope request: {url}")


class ScopeViolation(PermissionError):
    pass
