"""API Scanner quick view: dedicated API/GraphQL target checks."""
from __future__ import annotations

import customtkinter as ctk

from app.ui.theme import *


class ApiView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=BG)
        self.app = app
        ctk.CTkLabel(self, text="API Scanner", font=FONT_TITLE).pack(anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(self, text="REST / JSON / GraphQL basic analysis (auth, CORS, methods, disclosure).",
                     text_color=MUTED).pack(anchor="w", padx=16, pady=(0, 10))
        box = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8)
        box.pack(fill="x", padx=16, pady=6)
        ctk.CTkLabel(box, text="API base URL", font=FONT_SMALL, text_color=MUTED).pack(anchor="w", padx=14, pady=(10, 0))
        from app.config.settings import DEFAULT_TARGET, DEFAULT_SCOPE
        self.url = ctk.CTkEntry(box, width=520, placeholder_text="https://example.com/api")
        self.url.pack(anchor="w", padx=14, pady=4)
        if DEFAULT_TARGET:
            self.url.insert(0, DEFAULT_TARGET)
        self.scope = ctk.CTkEntry(box, width=520, placeholder_text="example.com")
        self.scope.pack(anchor="w", padx=14, pady=4)
        if DEFAULT_SCOPE:
            self.scope.insert(0, ", ".join(DEFAULT_SCOPE))
        row = ctk.CTkFrame(box, fg_color="transparent")
        row.pack(anchor="w", padx=14, pady=10)
        ctk.CTkButton(row, text="RUN API SCAN (passive)", width=220,
                      command=self._run).pack(side="left")
        self.out = ctk.CTkTextbox(self, font=FONT_MONO, height=300)
        self.out.pack(fill="both", expand=True, padx=16, pady=10)
        self.out.configure(state="disabled")

    def _run(self):
        self.app.start_scan(self.url.get().strip(), self.scope.get().strip(),
                            "passive", ["api", "headers", "jwt"], {}, {})

    def set_output(self, text: str):
        self.out.configure(state="normal")
        self.out.insert("end", text + "\n")
        self.out.see("end")
        self.out.configure(state="disabled")
