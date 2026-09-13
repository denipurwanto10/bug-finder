"""Reports view: export current results to HTML/PDF/JSON/CSV."""
from __future__ import annotations

from tkinter import filedialog

import customtkinter as ctk

from app.ui.theme import *


class ReportsView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=BG)
        self.app = app
        ctk.CTkLabel(self, text="Reports", font=FONT_TITLE).pack(anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(self, text="Export the current scan result. Report includes executive summary, scope, "
                                "methodology, score, findings, evidence, remediation, timeline, appendix.",
                     text_color=MUTED, wraplength=700, justify="left").pack(anchor="w", padx=16, pady=(0, 12))
        box = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8)
        box.pack(fill="x", padx=16, pady=6)
        self.info = ctk.CTkLabel(box, text="No scan loaded.", font=FONT_NORMAL)
        self.info.pack(anchor="w", padx=14, pady=10)
        row = ctk.CTkFrame(box, fg_color="transparent")
        row.pack(anchor="w", padx=14, pady=(0, 14))
        for fmt in ("HTML", "PDF", "JSON", "CSV"):
            ctk.CTkButton(row, text=f"Export {fmt}", width=140,
                          command=lambda f=fmt: self._export(f)).pack(side="left", padx=6)

    def refresh(self):
        n = len(self.app.current_findings)
        t = self.app.current_target or "—"
        self.info.configure(text=f"Current: {t}  |  {n} findings  |  score {self.app.current_score}")

    def _export(self, fmt: str):
        if not self.app.current_findings and self.app.current_score is None:
            self.app.log("Nothing to export — run a scan first")
            return
        ext = fmt.lower()
        path = filedialog.asksaveasfilename(defaultextension=f".{ext}",
                                            filetypes=[(fmt, f"*.{ext}")])
        if path:
            self.app.export_report(path, fmt.lower())
