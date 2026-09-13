"""History view: list, view, delete, compare, export."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

import customtkinter as ctk

from app.ui.theme import *
from app.ui.widgets import style_tree


class HistoryView(ctk.CTkFrame):
    def __init__(self, parent, app):
        super().__init__(parent, fg_color=BG)
        self.app = app
        ctk.CTkLabel(self, text="Scan History", font=FONT_TITLE).pack(anchor="w", padx=16, pady=(14, 6))
        self.tree = ttk.Treeview(self, columns=("id", "target", "mode", "score", "count", "date"),
                                 show="headings", height=18)
        for c, w, t in (("id", 60, "ID"), ("target", 320, "TARGET"), ("mode", 110, "MODE"),
                        ("score", 90, "SCORE"), ("count", 100, "FINDINGS"), ("date", 200, "DATE")):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w)
        style_tree(self.tree)
        self.tree.pack(fill="both", expand=True, padx=16, pady=6)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 14))
        ctk.CTkButton(row, text="Refresh", width=120, command=self.refresh).pack(side="left", padx=4)
        ctk.CTkButton(row, text="View", width=120, command=self._view).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Delete", width=120, fg_color=DANGER,
                      command=self._delete).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Compare 2 scans", width=150, command=self._compare).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Export Report", width=150, command=self._export).pack(side="left", padx=4)
        ctk.CTkButton(row, text="Clear All", width=120, fg_color=DANGER,
                      hover_color="#a83232", command=self._clear_all).pack(side="left", padx=4)

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for s in self.app.db.list_scans():
            self.tree.insert("", "end", iid=str(s["id"]), values=(
                s["id"], s["target"][:50], s["mode"], s["security_score"],
                s.get("finding_count", 0), s.get("created_at", "")))

    def _sel_ids(self):
        return [int(i) for i in self.tree.selection()]

    def _view(self):
        ids = self._sel_ids()
        if not ids:
            return
        self.app.load_scan_from_history(ids[0])

    def _delete(self):
        ids = self._sel_ids()
        if not ids:
            return
        if messagebox.askyesno("Delete", f"Delete scan(s) {ids}?"):
            for i in ids:
                self.app.db.delete_scan(i)
            self.refresh()

    def _compare(self):
        ids = self._sel_ids()
        if len(ids) != 2:
            messagebox.showinfo("Compare", "Select exactly 2 scans to compare.")
            return
        res = self.app.db.compare_scans(ids[0], ids[1])
        msg = (f"Scan {ids[0]}: {res['a_count']} findings\nScan {ids[1]}: {res['b_count']} findings\n\n"
               f"NEW in {ids[1]} ({len(res['new'])}):\n" +
               "\n".join(f"  + {n[0]} @ {n[1]} [{n[2]}]" for n in res["new"][:20]) +
               f"\n\nFIXED ({len(res['fixed'])}):\n" +
               "\n".join(f"  - {n[0]} @ {n[1]} [{n[2]}]" for n in res["fixed"][:20]))
        messagebox.showinfo(f"Compare {ids[0]} vs {ids[1]}", msg or "No differences.")

    def _export(self):
        ids = self._sel_ids()
        if not ids:
            return
        path = filedialog.asksaveasfilename(defaultextension=".html",
                                            filetypes=[("HTML", "*.html"), ("PDF", "*.pdf"),
                                                       ("JSON", "*.json"), ("CSV", "*.csv")])
        if path:
            self.app.export_history_report(ids[0], path)

    def _clear_all(self):
        if not messagebox.askyesno("Clear All History",
                                    "Hapus SEMUA riwayat scan dari database? Tindakan ini tidak bisa dibatalkan."):
            return
        for s in self.app.db.list_scans():
            self.app.db.delete_scan(s["id"])
        self.app.log("History cleared by user (all scans deleted)")
        self.refresh()
