"""Audit logging with secret redaction. Never store passwords/tokens/cookies."""
from __future__ import annotations

import logging
import re
from pathlib import Path

SECRET_PATTERNS = [
    (re.compile(r"(?i)(password\s*[=:]\s*)([^\s&;,'\"]+)"), r"\1***"),
    (re.compile(r"(?i)(passwd\s*[=:]\s*)([^\s&;,'\"]+)"), r"\1***"),
    (re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)([^\s&;,'\"]+)"), r"\1***"),
    (re.compile(r"(?i)(secret\s*[=:]\s*)([^\s&;,'\"]+)"), r"\1***"),
    (re.compile(r"(?i)(token\s*[=:]\s*)([^\s&;,'\"]+)"), r"\1***"),
    (re.compile(r"(?i)(authorization:\s*bearer\s+)(\S+)"), r"\1***"),
    (re.compile(r"(?i)(cookie:\s*)([^\n\r]+)"), r"\1***"),
    (re.compile(r"(?i)(set-cookie:\s*)([^\n\r]+)"), r"\1***"),
]


def redact(text: str) -> str:
    out = str(text or "")
    for rx, repl in SECRET_PATTERNS:
        out = rx.sub(repl, out)
    return out[:4000]


def get_audit_logger(path: str = "webguard_audit.log") -> logging.Logger:
    logger = logging.getLogger("webguard.audit")
    if not logger.handlers:
        logger.setLevel(logging.INFO)
        fh = logging.FileHandler(path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        logger.addHandler(fh)
    return logger


class AuditLog:
    def __init__(self, path: str = "webguard_audit.log", on_event=None):
        self.logger = get_audit_logger(path)
        self.on_event = on_event  # optional UI callback(str)

    def _emit(self, level: str, msg: str):
        clean = redact(msg)
        if level == "error":
            self.logger.error(clean)
        elif level == "warning":
            self.logger.warning(clean)
        else:
            self.logger.info(clean)
        if self.on_event:
            try:
                self.on_event(f"[{level.upper()}] {clean}")
            except Exception:
                pass

    def info(self, msg: str): self._emit("info", msg)
    def warning(self, msg: str): self._emit("warning", msg)
    def error(self, msg: str): self._emit("error", msg)

    def scan_started(self, target: str, mode: str, scope: list):
        self.info(f"scan started | target={target} | mode={mode} | scope={','.join(scope)}")

    def scan_completed(self, target: str, findings: int, score: int, requests: int, duration: float):
        self.info(f"scan completed | target={target} | findings={findings} "
                  f"| score={score} | requests={requests} | duration={duration:.1f}s")

    def scan_stopped(self, target: str, requests: int):
        self.warning(f"scan stopped | target={target} | requests={requests}")

    def finding(self, module: str, name: str, severity: str, url: str):
        self.info(f"finding | module={module} | {name} | severity={severity} | url={url}")

    def module_done(self, module: str, requests: int):
        self.info(f"module done | module={module} | requests={requests}")

    def request_count(self, module: str, count: int):
        self.info(f"module progress | module={module} | request count={count}")
