"""Shared data models: Target, Scope, Finding, ScanResult."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
from urllib.parse import urlparse
import ipaddress


@dataclass
class Target:
    url: str
    scope: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.url.startswith(("http://", "https://")):
            self.url = "http://" + self.url
        self.url = self.url.rstrip("/")
        if not self.scope:
            host = urlparse(self.url).hostname or ""
            if host:
                self.scope = [host]


@dataclass
class Finding:
    name: str
    severity: str  # Critical/High/Medium/Low/Informational
    confidence: str  # High/Medium/Low
    url: str
    method: str = "GET"
    parameter: str = ""
    evidence: str = ""
    request_summary: str = ""
    response_summary: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    module: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "severity": self.severity,
            "confidence": self.confidence, "url": self.url,
            "method": self.method, "parameter": self.parameter,
            "evidence": self.evidence, "request_summary": self.request_summary,
            "response_summary": self.response_summary,
            "description": self.description, "impact": self.impact,
            "remediation": self.remediation, "cwe": self.cwe,
            "owasp": self.owasp, "module": self.module,
            "references": list(self.references),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(**{k: d.get(k, "" if k != "references" else []) for k in
                      ("name", "severity", "confidence", "url", "method",
                       "parameter", "evidence", "request_summary",
                       "response_summary", "description", "impact",
                       "remediation", "cwe", "owasp", "module", "references")})

    def masked_dict(self) -> dict[str, Any]:
        from app.utils.helpers import mask_secrets
        d = self.to_dict()
        for k in ("evidence", "request_summary", "response_summary"):
            d[k] = mask_secrets(str(d.get(k, "")))
        return d


@dataclass
class PageInfo:
    url: str
    depth: int = 0
    status: int = 0
    title: str = ""
    forms: list[dict] = field(default_factory=list)
    get_params: list[str] = field(default_factory=list)
    js_files: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)


@dataclass
class ScanStats:
    pages_scanned: int = 0
    endpoints_found: int = 0
    parameters_tested: int = 0
    requests_sent: int = 0
    vulnerabilities_found: int = 0
    scan_duration: float = 0.0


@dataclass
class ScanResult:
    target: str
    scope: list[str]
    mode: str
    started_at: str = ""
    finished_at: str = ""
    security_score: int = 100
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    errors: list[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.started_at:
            self.started_at = datetime.now().isoformat(timespec="seconds")
