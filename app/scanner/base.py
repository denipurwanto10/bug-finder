"""Base class for all scanner modules: uniform finding output."""
from __future__ import annotations

from typing import Any, Optional

from app.scanner.http_client import HttpClient, StopRequested
from app.utils.logger import AuditLog
from app.utils.models import Finding


class BaseModule:
    name = "base"
    description = ""

    def __init__(self, client: HttpClient, audit: Optional[AuditLog] = None,
                 config=None, active: bool = False):
        self.client = client
        self.audit = audit or AuditLog()
        self.config = config
        self.active = active  # False = passive-only behavior
        self.findings: list[Finding] = []
        self.params_tested = 0

    def add_finding(self, **kwargs) -> Finding:
        kwargs.setdefault("module", self.name)
        f = Finding(**kwargs)
        self.findings.append(f)
        self.audit.finding(self.name, f.name, f.severity, f.url)
        return f

    async def run(self, target, pages, context: dict) -> list[Finding]:
        raise NotImplementedError

    def log(self, msg: str):
        self.audit.info(f"[{self.name}] {msg}")
