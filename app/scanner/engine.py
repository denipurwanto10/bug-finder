"""Orchestrated scan engine: crawl -> modules -> score, with STOP and audit log."""
from __future__ import annotations

import asyncio
import time
from datetime import datetime

from app.config.settings import AppConfig
from app.scanner.api import ApiModule
from app.scanner.auth import AuthModule
from app.scanner.authorization import AuthorizationModule
from app.scanner.base import BaseModule
from app.scanner.command_injection import CommandInjectionModule
from app.scanner.crawler import Crawler
from app.scanner.dependencies import DependenciesModule
from app.scanner.headers import HeadersModule
from app.scanner.http_client import HttpClient, StopRequested
from app.scanner.jwt import JwtModule
from app.scanner.misconfig import MisconfigModule
from app.scanner.sqli import SqliModule
from app.scanner.ssrf import SsrfModule
from app.scanner.tls import TlsModule
from app.scanner.traversal import TraversalModule
from app.scanner.upload import UploadModule
from app.scanner.xss import XssModule
from app.utils.helpers import compute_security_score
from app.utils.logger import AuditLog
from app.utils.models import ScanResult, Target

MODULES = {
    "xss": XssModule, "sqli": SqliModule, "cmdi": CommandInjectionModule,
    "traversal": TraversalModule, "ssrf": SsrfModule, "auth": AuthModule,
    "authorization": AuthorizationModule, "upload": UploadModule, "api": ApiModule,
    "jwt": JwtModule, "headers": HeadersModule, "tls": TlsModule,
    "dependencies": DependenciesModule, "misconfig": MisconfigModule,
}

PASSIVE_ONLY = {"headers", "tls", "dependencies", "jwt", "misconfig", "api"}


class ScanEngine:
    def __init__(self, config: AppConfig = None, audit: AuditLog = None,
                 progress_cb=None, log_cb=None):
        self.config = config or AppConfig()
        self.audit = audit or AuditLog(self.config.audit_log_path, on_event=log_cb)
        self.progress_cb = progress_cb
        self.client: HttpClient | None = None
        self._stopped = False

    def stop(self):
        self._stopped = True
        if self.client:
            self.client.stop()
        self.audit.warning("stop requested by user")

    def _progress(self, phase: str, pct: int, msg: str = ""):
        if self.progress_cb:
            try:
                self.progress_cb(phase, pct, msg)
            except Exception:
                pass

    async def run_scan(self, target: Target, mode: str = "passive",
                       modules: list[str] | None = None,
                       context: dict | None = None) -> ScanResult:
        context = context or {}
        t0 = time.monotonic()
        result = ScanResult(target=target.url, scope=list(target.scope), mode=mode)
        self.audit.scan_started(target.url, mode, target.scope)
        active = mode in ("active", "pentest")
        selected = modules or list(MODULES.keys())
        selected = [m for m in selected if m in MODULES]
        if mode == "passive":
            selected = [m for m in selected if not (m in ("sqli", "cmdi", "traversal") and True) or m in PASSIVE_ONLY or m in ("xss", "ssrf", "auth", "authorization", "upload")]
            # passive-safe subset: xss(dom only), ssrf(names), auth/cookies, api, jwt, headers, tls, deps, misconfig
            selected = [m for m in selected if m in ("xss", "ssrf", "auth", "authorization", "upload",
                                                      "api", "jwt", "headers", "tls", "dependencies", "misconfig")]

        lim = self.config.limits
        async with HttpClient(scope=target.scope, user_agent=self.config.user_agent,
                              rps=lim.requests_per_second, timeout=lim.timeout,
                              max_requests=lim.max_requests, audit=self.audit) as client:
            self.client = client
            duration_limit = lim.scan_duration
            try:
                # 1. crawl
                self._progress("crawl", 5, f"Crawling {target.url}")
                crawler = Crawler(client, audit=self.audit, depth=lim.crawl_depth,
                                  max_pages=lim.max_pages, max_workers=lim.concurrent_workers,
                                  progress_cb=lambda m: self._progress("crawl", 10, m))
                pages = await crawler.crawl(target.url)
                context["crawler"] = crawler
                result.stats.pages_scanned = len(pages)
                result.stats.endpoints_found = len(crawler.api_endpoints) + len(pages)
                self._progress("crawl", 20, f"{len(pages)} pages, {len(crawler.api_endpoints)} API endpoints")
                self.audit.info(f"crawl done | pages={len(pages)} endpoints={len(crawler.api_endpoints)}")

                # 2. modules
                total = len(selected)
                for i, mname in enumerate(selected):
                    if self._stopped or client.stopped:
                        raise StopRequested("Scan stopped by user")
                    if duration_limit and (time.monotonic() - t0) > duration_limit:
                        self.audit.warning(f"scan duration limit reached ({duration_limit}s)")
                        break
                    cls = MODULES[mname]
                    mod = cls(client, audit=self.audit, config=self.config, active=active)
                    self._progress(mname, 20 + int(75 * i / max(1, total)), f"Running {mname}")
                    self.audit.info(f"module started | module={mname} | active={active}")
                    try:
                        findings = await mod.run(target, pages, context)
                    except StopRequested:
                        raise
                    except Exception as e:
                        msg = f"module error | module={mname} | {e}"
                        self.audit.error(msg)
                        result.errors.append(msg)
                        continue
                    result.findings.extend(findings)
                    result.stats.parameters_tested += mod.params_tested
                    self.audit.module_done(mname, client.requests_sent)
                    self._progress(mname, 20 + int(75 * (i + 1) / max(1, total)),
                                   f"{mname}: {len(findings)} findings")
                # central dedup: (name, url, param) — keeps dashboard/score honest
                seen: set[tuple] = set()
                uniq: list = []
                for f in result.findings:
                    key = (f.name, f.url, f.parameter)
                    if key not in seen:
                        seen.add(key)
                        uniq.append(f)
                if len(uniq) != len(result.findings):
                    self.audit.info(f"dedup removed {len(result.findings) - len(uniq)} duplicate findings")
                    result.findings = uniq
            except StopRequested as e:
                result.errors.append(str(e))
                self.audit.scan_stopped(target.url, client.requests_sent)
            finally:
                result.stats.requests_sent = client.requests_sent
                result.stats.scan_duration = time.monotonic() - t0
                result.stats.vulnerabilities_found = len(result.findings)
                result.security_score = compute_security_score(result.findings)
                result.finished_at = datetime.now().isoformat(timespec="seconds")
                self._progress("done", 100, f"Score {result.security_score} | {len(result.findings)} findings")
                if not self._stopped:
                    self.audit.scan_completed(target.url, len(result.findings),
                                              result.security_score, client.requests_sent,
                                              result.stats.scan_duration)
                self.client = None
        return result
