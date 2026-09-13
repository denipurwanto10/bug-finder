"""Central application configuration for WebGuard Pro."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanLimits:
    requests_per_second: float = 5.0
    max_requests: int = 500
    timeout: float = 15.0
    crawl_depth: int = 2
    concurrent_workers: int = 5
    max_payload_size: int = 4096
    scan_duration: int = 600  # seconds, 0 = unlimited
    max_pages: int = 100
    max_params_per_page: int = 10


@dataclass
class AppConfig:
    app_name: str = "WebGuard Pro"
    version: str = "1.0.0"
    user_agent: str = "WebGuardPro/1.0 (Authorized Security Scanner)"
    db_path: str = "webguard.db"
    audit_log_path: str = "webguard_audit.log"
    report_dir: str = "reports_output"
    limits: ScanLimits = field(default_factory=ScanLimits)

    # Safe-verification toggles (never destructive)
    time_based_sqli_delay: float = 2.0
    time_based_cmdi_delay: float = 2.0
    login_max_attempts: int = 5

    def to_dict(self) -> dict:
        return {
            "app_name": self.app_name,
            "version": self.version,
            "db_path": self.db_path,
            "limits": {
                "requests_per_second": self.limits.requests_per_second,
                "max_requests": self.limits.max_requests,
                "timeout": self.limits.timeout,
                "crawl_depth": self.limits.crawl_depth,
                "concurrent_workers": self.limits.concurrent_workers,
                "max_payload_size": self.limits.max_payload_size,
                "scan_duration": self.limits.scan_duration,
                "max_pages": self.limits.max_pages,
            },
        }


DEFAULT_CONFIG = AppConfig()

# Nilai awal kolom target/scope — kosong: pengguna wajib mengisi sendiri.
DEFAULT_TARGET = ""
DEFAULT_SCOPE: list = []

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}

SEVERITY_WEIGHTS = {"Critical": 25, "High": 10, "Medium": 4, "Low": 1, "Informational": 0}
