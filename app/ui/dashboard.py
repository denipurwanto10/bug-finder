"""Dashboard view: score, severity cards, progress, recent findings, log panel."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from app.ui.theme import *
from app.ui.widgets import style_tree


class DashboardView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=BG)
        self.app = app
        # top row
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.pack(fill="x", padx=16, pady=(14, 6))
        self.score_box = ctk.CTkFrame(top, fg_color=PANEL, corner_radius=8, width=200)
        self.score_box.pack(side="left", padx=(0, 12), fill="y")
        ctk.CTkLabel(self.score_box, text="SECURITY SCORE", font=FONT_SMALL,
                     text_color=MUTED).pack(pady=(12, 0))
        self.score_lbl = ctk.CTkLabel(self.score_box, text="—", font=("Segoe UI", 40, "bold"))
        self.score_lbl.pack(padx=30, pady=(0, 12))
        self.cards = {}
        cardrow = ctk.CTkFrame(top, fg_color="transparent")
        cardrow.pack(side="left", fill="both", expand=True)
        for sev in ("Critical", "High", "Medium", "Low", "Informational"):
            f = ctk.CTkFrame(cardrow, fg_color=PANEL, corner_radius=8)
            f.pack(side="left", fill="both", expand=True, padx=4)
            ctk.CTkLabel(f, text=sev.upper(), font=FONT_SMALL, text_color=MUTED).pack(pady=(10, 0))
            lbl = ctk.CTkLabel(f, text="0", font=("Segoe UI", 22, "bold"),
                               text_color=SEV_COLORS[sev])
            lbl.pack(pady=(0, 10))
            self.cards[sev] = lbl
        # progress
        prog = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8)
        prog.pack(fill="x", padx=16, pady=6)
        self.phase_lbl = ctk.CTkLabel(prog, text="Idle", font=FONT_NORMAL, anchor="w")
        self.phase_lbl.pack(fill="x", padx=14, pady=(10, 2))
        self.progress = ctk.CTkProgressBar(prog)
        self.progress.pack(fill="x", padx=14, pady=(0, 12))
        self.progress.set(0)
        # middle: recent findings + stats
        mid = ctk.CTkFrame(self, fg_color="transparent")
        mid.pack(fill="both", expand=True, padx=16, pady=6)
        left = ctk.CTkFrame(mid, fg_color=PANEL, corner_radius=8)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        ctk.CTkLabel(left, text="Recent Findings", font=FONT_H2).pack(anchor="w", padx=14, pady=(10, 4))
        self.tree = ttk.Treeview(left, columns=("sev", "name", "url"), show="headings", height=9)
        for c, w in (("sev", 110), ("name", 260), ("url", 320)):
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=w)
        style_tree(self.tree)
        self.tree.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        right = ctk.CTkFrame(mid, fg_color=PANEL, corner_radius=8, width=250)
        right.pack(side="left", fill="y", padx=(6, 0))
        ctk.CTkLabel(right, text="Scan Statistics", font=FONT_H2).pack(anchor="w", padx=14, pady=(10, 4))
        self.stats_lbl = ctk.CTkLabel(right, text="No scan yet.", font=FONT_SMALL,
                                      text_color=MUTED, justify="left", anchor="w")
        self.stats_lbl.pack(anchor="w", padx=14, pady=6)
        # log panel
        logf = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8)
        logf.pack(fill="both", padx=16, pady=(6, 14))
        ctk.CTkLabel(logf, text="Activity / Audit Log", font=FONT_H2).pack(anchor="w", padx=14, pady=(10, 4))
        self.logbox = ctk.CTkTextbox(logf, height=110, font=FONT_MONO)
        self.logbox.pack(fill="both", padx=12, pady=(0, 12))
        self.logbox.configure(state="disabled")

    def set_score(self, score, counts):
        self.score_lbl.configure(text=str(score))
        color = OK if score >= 80 else (WARN if score >= 50 else DANGER)
        self.score_lbl.configure(text_color=color)
        for k, v in counts.items():
            if k in self.cards:
                self.cards[k].configure(text=str(v))

    def set_progress(self, phase, pct, msg=""):
        self.phase_lbl.configure(text=f"{phase} — {msg}" if msg else phase)
        self.progress.set(max(0, min(100, pct)) / 100)

    def set_recent(self, findings):
        self.tree.delete(*self.tree.get_children())
        for f in (findings or [])[-15:][::-1]:
            d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            self.tree.insert("", "end", values=(d.get("severity", ""), d.get("name", "")[:60],
                                                d.get("url", "")[:70]),
                             tags=(f"sev-{d.get('severity','')}",))

    def set_stats(self, stats):
        if not stats:
            return
        self.stats_lbl.configure(text=(
            f"Pages scanned: {stats.pages_scanned}\nEndpoints: {stats.endpoints_found}\n"
            f"Params tested: {stats.parameters_tested}\nRequests: {stats.requests_sent}\n"
            f"Vulns: {stats.vulnerabilities_found}\nDuration: {stats.scan_duration:.1f}s"))

    def append_log(self, line: str):
        self.logbox.configure(state="normal")
        self.logbox.insert("end", line + "\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")
