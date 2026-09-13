"""Settings view: theme + default safety limits."""
from __future__ import annotations

import customtkinter as ctk

from app.config.settings import AppConfig
from app.ui.theme import *


class SettingsView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=BG)
        self.app = app
        ctk.CTkLabel(self, text="Settings", font=FONT_TITLE).pack(anchor="w", padx=16, pady=(14, 6))
        box = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8)
        box.pack(fill="x", padx=16, pady=6)
        ctk.CTkLabel(box, text="Appearance", font=FONT_H2).pack(anchor="w", padx=14, pady=(10, 4))
        self.theme = ctk.CTkOptionMenu(box, values=["Dark", "Light", "System"],
                                       command=lambda v: ctk.set_appearance_mode(v))
        self.theme.pack(anchor="w", padx=14, pady=(0, 12))
        self.theme.set("Dark")
        lim = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8)
        lim.pack(fill="x", padx=16, pady=6)
        ctk.CTkLabel(lim, text="Default Safety Limits", font=FONT_H2).pack(anchor="w", padx=14, pady=(10, 4))
        d = AppConfig().limits
        txt = (f"Requests/sec: {d.requests_per_second}   Max requests: {d.max_requests}   "
               f"Timeout: {d.timeout}s\nDepth: {d.crawl_depth}   Workers: {d.concurrent_workers}   "
               f"Max pages: {d.max_pages}   Duration: {d.scan_duration}s\n\n"
               "Per-scan overrides live on the New Scan page. Safety controls always apply; "
               "STOP SCAN halts all active requests immediately.")
        ctk.CTkLabel(lim, text=txt, font=FONT_SMALL, text_color=MUTED,
                     justify="left").pack(anchor="w", padx=14, pady=(0, 12))
        eth = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8)
        eth.pack(fill="x", padx=16, pady=6)
        ctk.CTkLabel(eth, text="Authorized Use Only", font=FONT_H2).pack(anchor="w", padx=14, pady=(10, 4))
        ctk.CTkLabel(eth, wraplength=700, justify="left", font=FONT_SMALL, text_color=MUTED,
                     text="WebGuard Pro is an authorized testing toolkit. Scan only systems you own "
                          "or have written permission to test. Do not use test-account credentials "
                          "outside their designated scope. All activity is written to the audit log.").pack(
            anchor="w", padx=14, pady=(0, 12))
