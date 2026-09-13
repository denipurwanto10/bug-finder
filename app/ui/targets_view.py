"""Targets view: quick authorized-target presets + scope hints."""
from __future__ import annotations

import customtkinter as ctk

from app.ui.theme import *


class TargetsView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=BG)
        self.app = app
        ctk.CTkLabel(self, text="Targets", font=FONT_TITLE).pack(anchor="w", padx=16, pady=(14, 4))
        ctk.CTkLabel(self, wraplength=700, justify="left", text_color=MUTED,
                     text="Only scan targets you own or have written permission to test. "
                          "Requests outside the declared scope are blocked automatically.").pack(
            anchor="w", padx=16, pady=(0, 10))
        presets = [
            ("testphp.vulnweb.com", "http://testphp.vulnweb.com", "testphp.vulnweb.com",
             "Intentionally vulnerable demo site by Acunetix for testing."),
            ("testhtml5.vulnweb.com", "http://testhtml5.vulnweb.com", "testhtml5.vulnweb.com",
             "Acunetix HTML5 demo target."),
            ("Local TestLab (opsional)", "http://127.0.0.1:8765", "127.0.0.1",
             "Run test_target.py first. Safe local demo target."),
        ]
        for name, url, scope, desc in presets:
            card = ctk.CTkFrame(self, fg_color=PANEL, corner_radius=8)
            card.pack(fill="x", padx=16, pady=5)
            ctk.CTkLabel(card, text=name, font=FONT_H2).pack(anchor="w", padx=14, pady=(10, 0))
            ctk.CTkLabel(card, text=f"{url}   |   scope: {scope}", font=FONT_MONO,
                         text_color=MUTED).pack(anchor="w", padx=14)
            ctk.CTkLabel(card, text=desc, font=FONT_SMALL, text_color=MUTED).pack(
                anchor="w", padx=14, pady=(0, 4))
            ctk.CTkButton(card, text="Use in New Scan", width=160,
                          command=lambda u=url, s=scope: self.app.use_target(u, s)).pack(
                anchor="w", padx=14, pady=(0, 12))
