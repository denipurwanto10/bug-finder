"""Vulnerabilities view: filter + search + detail panel."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from app.ui.theme import *
from app.ui.widgets import style_tree, fill_findings_tree, show_finding_detail


class VulnView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=BG)
        self.app = app
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.pack(fill="x", padx=16, pady=(14, 6))
        ctk.CTkLabel(bar, text="Vulnerabilities", font=FONT_TITLE).pack(side="left")
        self.search = ctk.CTkEntry(bar, placeholder_text="Search name / URL / param...", width=280)
        self.search.pack(side="right", padx=(8, 0))
        self.search.bind("<KeyRelease>", lambda e: self.refresh())
        self.sev_filter = tk.StringVar(value="All")
        ctk.CTkOptionMenu(bar, variable=self.sev_filter, values=["All", "Critical", "High",
                          "Medium", "Low", "Informational"],
                          command=lambda _: self.refresh(), width=150).pack(side="right")
        self.tree = ttk.Treeview(self, columns=("sev", "name", "url", "param", "conf"),
                                 show="headings", height=22)
        for c, w, t in (("sev", 110, "SEVERITY"), ("name", 300, "NAME"),
                        ("url", 380, "URL"), ("param", 160, "PARAM"),
                        ("conf", 110, "CONF")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w)
        style_tree(self.tree)
        self.tree.pack(fill="both", expand=True, padx=16, pady=6)
        self.tree.bind("<Double-1>", self._open_detail)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 14))
        ctk.CTkButton(row, text="View Detail", width=140, command=self._open_detail).pack(side="left")

    def refresh(self):
        fill_findings_tree(self.tree, self.app.current_findings,
                           self.sev_filter.get(), self.search.get())

    def _open_detail(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        # map through current filter: find nth visible finding
        visible = self._visible()
        if 0 <= idx < len(self.tree.get_children()):
            # iid == original index
            orig = int(sel[0])
            if orig < len(self.app.current_findings):
                show_finding_detail(self, self.app.current_findings[orig])

    def _visible(self):
        return self.tree.get_children()
