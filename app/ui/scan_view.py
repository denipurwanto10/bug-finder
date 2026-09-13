"""New Scan view: target, scope, mode, modules, safety limits, auth context, STOP."""
from __future__ import annotations

import tkinter as tk

import customtkinter as ctk

from app.config.settings import AppConfig
from app.ui.theme import *
from app.ui.widgets import ask_authorization_confirm


class NewScanView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=BG)
        self.app = app
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=16, pady=12)

        ctk.CTkLabel(scroll, text="New Scan", font=FONT_TITLE).pack(anchor="w", pady=(0, 10))

        # target & scope
        from app.config.settings import DEFAULT_TARGET, DEFAULT_SCOPE
        box = self._box(scroll, "Target & Scope (authorized targets only)")
        ctk.CTkLabel(box, text="Target URL / domain / IP").pack(anchor="w")
        self.target_entry = ctk.CTkEntry(box, placeholder_text="https://example.com", width=520)
        self.target_entry.pack(anchor="w", pady=4)
        if DEFAULT_TARGET:
            self.target_entry.insert(0, DEFAULT_TARGET)
        ctk.CTkLabel(box, text="Scope (comma-separated hosts, e.g. example.com, api.example.com)").pack(anchor="w", pady=(8, 0))
        self.scope_entry = ctk.CTkEntry(box, placeholder_text="example.com", width=520)
        self.scope_entry.pack(anchor="w", pady=4)
        if DEFAULT_SCOPE:
            self.scope_entry.insert(0, ", ".join(DEFAULT_SCOPE))
        ctk.CTkLabel(box, text="Scan mode", font=FONT_SMALL, text_color=MUTED).pack(anchor="w", pady=(8, 0))
        self.mode_var = tk.StringVar(value="passive")
        modes = ctk.CTkFrame(box, fg_color="transparent")
        modes.pack(anchor="w", pady=4)
        for m in ("passive", "active", "pentest"):
            ctk.CTkRadioButton(modes, text=m.title(), variable=self.mode_var, value=m).pack(side="left", padx=10)

        # modules
        mbox = self._box(scroll, "Modules")
        self.mod_vars = {}
        grid = ctk.CTkFrame(mbox, fg_color="transparent")
        grid.pack(anchor="w")
        mods = ["xss", "sqli", "cmdi", "traversal", "ssrf", "auth", "authorization",
                "upload", "api", "jwt", "headers", "tls", "dependencies", "misconfig"]
        for i, m in enumerate(mods):
            v = tk.BooleanVar(value=True)
            ctk.CTkCheckBox(grid, text=m, variable=v).grid(row=i // 4, column=i % 4,
                                                           padx=12, pady=4, sticky="w")
            self.mod_vars[m] = v

        # pentest context
        pbox = self._box(scroll, "Authorized Pentest Context (optional)")
        self.login_url = self._entry(pbox, "Login URL", "")
        self.username = self._entry(pbox, "Test account username (pentest only)", "")
        self.password = self._entry(pbox, "Test account password (never stored in logs)", "", show="*")
        self.session_a = self._entry(pbox, "Test session cookie A (IDOR differential)", "")
        self.session_b = self._entry(pbox, "Test session cookie B (IDOR differential)", "")
        self.ssrf_cb = self._entry(pbox, "Your SSRF callback endpoint (e.g. https://your-server/cb)", "")
        self.jwt_in = self._entry(pbox, "Sample JWT to analyze (optional)", "")

        # limits
        lbox = self._box(scroll, "Rate Limiting & Safety Controls")
        lim = AppConfig().limits
        self.rps = self._entry(lbox, "Requests per second", str(lim.requests_per_second))
        self.maxreq = self._entry(lbox, "Maximum requests", str(lim.max_requests))
        self.timeout = self._entry(lbox, "Timeout (s)", str(lim.timeout))
        self.depth = self._entry(lbox, "Crawl depth", str(lim.crawl_depth))
        self.workers = self._entry(lbox, "Concurrent workers", str(lim.concurrent_workers))
        self.maxpages = self._entry(lbox, "Max pages", str(lim.max_pages))
        self.duration = self._entry(lbox, "Scan duration limit (s, 0=unlimited)", str(lim.scan_duration))

        # actions
        row = ctk.CTkFrame(scroll, fg_color="transparent")
        row.pack(fill="x", pady=14)
        self.start_btn = ctk.CTkButton(row, text="START SCAN", width=180, height=38,
                                       fg_color=ACCENT, hover_color=ACCENT_HOVER,
                                       command=self._on_start)
        self.start_btn.pack(side="left", padx=(0, 10))
        self.stop_btn = ctk.CTkButton(row, text="STOP SCAN", width=180, height=38,
                                      fg_color=DANGER, hover_color="#a83232",
                                      command=self.app.stop_scan, state="disabled")
        self.stop_btn.pack(side="left")

    def _box(self, parent, title):
        f = ctk.CTkFrame(parent, fg_color=PANEL, corner_radius=8)
        f.pack(fill="x", pady=6)
        ctk.CTkLabel(f, text=title, font=FONT_H2).pack(anchor="w", padx=14, pady=(10, 6))
        inner = ctk.CTkFrame(f, fg_color="transparent")
        inner.pack(fill="x", padx=14, pady=(0, 12))
        return inner

    def _entry(self, parent, label, default, show=None):
        ctk.CTkLabel(parent, text=label, font=FONT_SMALL, text_color=MUTED).pack(anchor="w", pady=(6, 0))
        e = ctk.CTkEntry(parent, width=520, show=show or "")
        e.pack(anchor="w", pady=2)
        if default:
            e.insert(0, default)
        return e

    def set_running(self, running: bool):
        self.start_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")

    def _on_start(self):
        mode = self.mode_var.get()
        if mode in ("active", "pentest"):
            if not ask_authorization_confirm(self, mode):
                return
        try:
            limits = {
                "requests_per_second": float(self.rps.get() or 5),
                "max_requests": int(self.maxreq.get() or 500),
                "timeout": float(self.timeout.get() or 15),
                "crawl_depth": int(self.depth.get() or 2),
                "concurrent_workers": int(self.workers.get() or 5),
                "max_pages": int(self.maxpages.get() or 100),
                "scan_duration": int(self.duration.get() or 600),
            }
        except ValueError:
            self.app.log("Invalid numeric limit; using defaults")
            limits = {}
        modules = [m for m, v in self.mod_vars.items() if v.get()]
        context = {
            "login_url": self.login_url.get().strip(),
            "username": self.username.get(),
            "password": self.password.get(),
            "session_a": self.session_a.get().strip(),
            "session_b": self.session_b.get().strip(),
            "ssrf_callback": self.ssrf_cb.get().strip(),
            "jwt": self.jwt_in.get().strip(),
        }
        self.app.start_scan(self.target_entry.get().strip(),
                            self.scope_entry.get().strip(), mode, modules,
                            limits, context)
