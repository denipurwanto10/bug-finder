"""Main application shell: sidebar navigation + scan orchestration."""
from __future__ import annotations

import asyncio
import json
import threading
import traceback
from datetime import datetime
from tkinter import messagebox

import customtkinter as ctk

from app.config.settings import AppConfig
from app.database.db import ScanDB
from app.reports.generator import export_csv, export_html, export_json, export_pdf
from app.scanner.engine import ScanEngine
from app.ui.api_view import ApiView
from app.ui.dashboard import DashboardView
from app.ui.history_view import HistoryView
from app.ui.pentest_view import PentestView
from app.ui.reports_view import ReportsView
from app.ui.scan_view import NewScanView
from app.ui.settings_view import SettingsView
from app.ui.targets_view import TargetsView
from app.ui.theme import BG, PANEL
from app.ui.vuln_view import VulnView
from app.utils.helpers import is_valid_url, severity_counts
from app.utils.logger import AuditLog
from app.utils.models import Finding, ScanResult, Target

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


class WebGuardApp(ctk.CTk):
    def __init__(self, config: AppConfig | None = None):
        super().__init__()
        self.config = config or AppConfig()
        self.title(f"{self.config.app_name} {self.config.version} — Authorized Web Security Scanner")
        self.geometry("1280x820")
        self.minsize(1080, 700)

        self.db = ScanDB(self.config.db_path)
        self.audit = AuditLog(self.config.audit_log_path, on_event=self._on_audit_event)
        self.engine: ScanEngine | None = None
        self.scan_thread: threading.Thread | None = None
        self.scanning = False

        self.current_findings: list[Finding] = []
        self.current_target = ""
        self.current_scope: list[str] = []
        self.current_mode = ""
        self.current_score: int | None = None
        self.current_stats = None
        self.timeline: list[str] = []

        # layout
        self.sidebar = ctk.CTkFrame(self, fg_color=PANEL, width=200, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        ctk.CTkLabel(self.sidebar, text="🛡 WebGuard Pro",
                     font=("Segoe UI", 16, "bold")).pack(pady=(18, 2))
        ctk.CTkLabel(self.sidebar, text="Authorized Scanner",
                     font=("Segoe UI", 11), text_color="#8a93a3").pack(pady=(0, 14))
        self.nav_buttons = {}
        self.content = ctk.CTkFrame(self, fg_color=BG)
        self.content.pack(side="left", fill="both", expand=True)

        self.views = {
            "Dashboard": DashboardView(self.content, self),
            "New Scan": NewScanView(self.content, self),
            "Targets": TargetsView(self.content, self),
            "Vulnerabilities": VulnView(self.content, self),
            "API Scanner": ApiView(self.content, self),
            "Pentest": PentestView(self.content, self),
            "History": HistoryView(self.content, self),
            "Reports": ReportsView(self.content, self),
            "Settings": SettingsView(self.content, self),
        }
        for name in self.views:
            btn = ctk.CTkButton(self.sidebar, text=name, anchor="w", width=180,
                                fg_color="transparent", text_color="#dfe6ef",
                                hover_color="#1a2330",
                                command=lambda n=name: self.show(n))
            btn.pack(padx=10, pady=2)
            self.nav_buttons[name] = btn
        self.show("Dashboard")
        self.log(f"{self.config.app_name} {self.config.version} ready. Scope enforcement ON.")

    # ---- navigation ----
    def show(self, name: str):
        for v in self.views.values():
            v.pack_forget()
        self.views[name].pack(fill="both", expand=True)
        for n, b in self.nav_buttons.items():
            b.configure(fg_color="#1f6feb" if n == name else "transparent")
        if name == "Vulnerabilities":
            self.views[name].refresh()
        if name == "History":
            self.views[name].refresh()
        if name == "Reports":
            self.views[name].refresh()

    # ---- logging ----
    def _on_audit_event(self, line: str):
        try:
            self.after(0, lambda: self.views["Dashboard"].append_log(line))
        except Exception:
            pass

    def log(self, msg: str):
        self.audit.info(msg)

    # ---- scan control ----
    def use_target(self, url: str, scope: str):
        nv: NewScanView = self.views["New Scan"]
        nv.target_entry.delete(0, "end")
        nv.target_entry.insert(0, url)
        nv.scope_entry.delete(0, "end")
        nv.scope_entry.insert(0, scope)
        self.show("New Scan")

    def start_scan(self, target_url: str, scope_raw: str, mode: str,
                   modules, limits: dict, context: dict):
        if self.scanning:
            messagebox.showinfo("Scan", "A scan is already running. Stop it first.")
            return
        if not target_url or not is_valid_url(target_url):
            messagebox.showerror("Target", "Enter a valid http(s) target URL.")
            return
        scope = [s.strip().lower().rstrip(".").lstrip("*.") for s in (scope_raw or "").split(",") if s.strip()]
        if not scope:
            from urllib.parse import urlparse
            scope = [(urlparse(target_url).hostname or "").lower()]
        # scope sanity: target host must be in scope
        from app.utils.scope import host_in_scope
        from urllib.parse import urlparse as _up
        if not host_in_scope(_up(target_url).hostname or "", scope):
            messagebox.showerror("Scope", "Target host is not inside the declared scope. Fix scope first.")
            return
        cfg = AppConfig()
        if limits:
            for k, v in limits.items():
                if hasattr(cfg.limits, k):
                    setattr(cfg.limits, k, v)
        # wipe password copies ASAP: keep only in local context for this run
        self.timeline = [f"{datetime.now().isoformat(timespec='seconds')} scan started ({mode}) {target_url}"]
        self.current_findings, self.current_score, self.current_stats = [], None, None
        self.current_target, self.current_scope, self.current_mode = target_url, scope, mode
        self.scanning = True
        self.views["New Scan"].set_running(True)
        self.show("Dashboard")
        self.views["Dashboard"].set_progress("starting", 2, target_url)
        target = Target(url=target_url, scope=scope)
        engine = ScanEngine(config=cfg, audit=self.audit,
                            progress_cb=self._on_progress, log_cb=None)
        self.engine = engine

        def _runner():
            try:
                result = asyncio.run(engine.run_scan(target, mode=mode,
                                                     modules=modules, context=context))
                self.after(0, lambda: self._on_scan_done(result))
            except Exception as e:
                traceback.print_exc()
                self.after(0, lambda: self._on_scan_error(str(e)))
            finally:
                # drop credential material
                context.pop("password", None)
                context.pop("session_a", None)
                context.pop("session_b", None)

        self.scan_thread = threading.Thread(target=_runner, daemon=True)
        self.scan_thread.start()

    def _on_progress(self, phase, pct, msg=""):
        try:
            self.after(0, lambda: self.views["Dashboard"].set_progress(phase, pct, msg))
        except Exception:
            pass

    def _on_scan_done(self, result: ScanResult):
        self.scanning = False
        self.views["New Scan"].set_running(False)
        self.current_findings = result.findings
        self.current_score = result.security_score
        self.current_stats = result.stats
        self.current_target, self.current_scope, self.current_mode = (
            result.target, result.scope, result.mode)
        self.timeline.append(f"{result.finished_at} scan finished: "
                             f"{len(result.findings)} findings, score {result.security_score}")
        counts = severity_counts(result.findings)
        dash = self.views["Dashboard"]
        dash.set_score(result.security_score, counts)
        dash.set_recent(result.findings)
        dash.set_stats(result.stats)
        dash.set_progress("done", 100, f"{len(result.findings)} findings, score {result.security_score}")
        # persist
        try:
            scan_id = self.db.save_scan(result)
            self.log(f"Scan saved to history (id={scan_id})")
        except Exception as e:
            self.log(f"History save failed: {e}")
        self.show("Dashboard")
        if result.errors:
            messagebox.showwarning("Scan finished with notes",
                                   f"{len(result.findings)} findings, score {result.security_score}.\n"
                                   f"Notes: {result.errors[0][:300]}")

    def _on_scan_error(self, err: str):
        self.scanning = False
        self.views["New Scan"].set_running(False)
        self.log(f"Scan error: {err}")
        messagebox.showerror("Scan error", err[:500])

    def stop_scan(self):
        if self.engine:
            self.engine.stop()
        self.log("STOP SCAN pressed")

    # ---- history / reports ----
    def load_scan_from_history(self, scan_id: int):
        d = self.db.get_scan(scan_id)
        if not d:
            return
        import json as _json
        self.current_findings = [Finding.from_dict({
            "name": f["name"], "severity": f["severity"], "confidence": f["confidence"],
            "url": f["url"], "method": f["method"], "parameter": f["parameter"],
            "evidence": f["evidence"], "request_summary": f["request_summary"],
            "response_summary": f["response_summary"], "description": f["description"],
            "impact": f["impact"], "remediation": f["remediation"], "cwe": f["cwe"],
            "owasp": f["owasp"], "module": f["module"],
            "references": _json.loads(f.get("references_json") or "[]")}) for f in d["findings"]]
        self.current_target = d["target"]
        self.current_scope = _json.loads(d.get("scope") or "[]")
        self.current_mode = d["mode"]
        self.current_score = d["security_score"]
        import types
        stats = _json.loads(d.get("stats") or "{}")
        self.current_stats = types.SimpleNamespace(**{**{
            "pages_scanned": 0, "endpoints_found": 0, "parameters_tested": 0,
            "requests_sent": 0, "vulnerabilities_found": len(self.current_findings),
            "scan_duration": 0.0}, **stats})
        dash = self.views["Dashboard"]
        dash.set_score(self.current_score, severity_counts(self.current_findings))
        dash.set_recent(self.current_findings)
        dash.set_stats(self.current_stats)
        self.show("Vulnerabilities")

    def _report_args(self):
        stats = {}
        if self.current_stats is not None:
            s = self.current_stats
            stats = s if isinstance(s, dict) else s.__dict__
        return (self.current_target, self.current_scope, self.current_mode,
                self.current_score or 0, self.current_findings, stats, self.timeline)

    def export_report(self, path: str, fmt: str):
        t, scope, mode, score, findings, stats, tl = self._report_args()
        try:
            if fmt == "html":
                export_html(path, t, scope, mode, score, findings, stats, tl)
            elif fmt == "pdf":
                export_pdf(path, t, scope, mode, score, findings, stats, tl)
            elif fmt == "json":
                export_json(path, t, scope, mode, score, findings, stats, tl)
            elif fmt == "csv":
                export_csv(path, findings)
            self.log(f"Report exported: {path}")
            messagebox.showinfo("Report", f"Saved to {path}")
        except Exception as e:
            messagebox.showerror("Report", f"Export failed: {e}")

    def export_history_report(self, scan_id: int, path: str):
        self.load_scan_from_history(scan_id)
        fmt = path.rsplit(".", 1)[-1].lower()
        if fmt not in ("html", "pdf", "json", "csv"):
            fmt = "html"
        self.export_report(path, fmt)
