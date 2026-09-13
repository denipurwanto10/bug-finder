"""Reusable widgets: severity badge colors, finding detail dialog, confirm modal."""
from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from app.ui.theme import SEV_COLORS, PANEL, BORDER, TEXT, MUTED, FONT_NORMAL, FONT_SMALL, FONT_MONO


def style_tree(tree: ttk.Treeview):
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    style.configure("WG.Treeview", background="#151d27", foreground="#dfe6ef",
                    fieldbackground="#151d27", rowheight=26, font=("Segoe UI", 11))
    style.configure("WG.Treeview.Heading", background="#1a2330", foreground="#8a93a3",
                    font=("Segoe UI", 11, "bold"))
    style.map("WG.Treeview", background=[("selected", "#1f6feb")])
    tree.configure(style="WG.Treeview")
    for sev, color in SEV_COLORS.items():
        tree.tag_configure(f"sev-{sev}", foreground=color)


def fill_findings_tree(tree: ttk.Treeview, findings, severity_filter="All", search=""):
    tree.delete(*tree.get_children())
    s = (search or "").lower()
    for i, f in enumerate(findings):
        d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        if severity_filter != "All" and d.get("severity") != severity_filter:
            continue
        if s and s not in f"{d.get('name','')} {d.get('url','')} {d.get('parameter','')}".lower():
            continue
        tree.insert("", "end", iid=str(i), values=(
            d.get("severity", ""), d.get("name", "")[:70],
            d.get("url", "")[:80], d.get("parameter", "")[:30],
            d.get("confidence", "")), tags=(f"sev-{d.get('severity','')}",))


def show_finding_detail(parent, finding) -> None:
    d = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
    win = ctk.CTkToplevel(parent)
    win.title(f"Finding — {d.get('name','')[:60]}")
    win.geometry("720x640")
    win.transient(parent)
    box = ctk.CTkTextbox(win, font=FONT_MONO)
    box.pack(fill="both", expand=True, padx=12, pady=12)
    fields = ["name", "severity", "confidence", "cwe", "owasp", "url", "method",
              "parameter", "evidence", "request_summary", "response_summary",
              "description", "impact", "remediation", "module"]
    text = ""
    for k in fields:
        text += f"{k.upper()}\n  {d.get(k, '')}\n\n"
    refs = d.get("references") or []
    text += "REFERENCES\n" + ("\n".join(f"  - {r}" for r in refs) if refs else "  -")
    box.insert("1.0", text)
    box.configure(state="disabled")


def ask_authorization_confirm(parent, mode: str) -> bool:
    """Modal requiring explicit ownership/permission checkbox before active scans."""
    result = {"ok": False}
    win = ctk.CTkToplevel(parent)
    win.title("Authorization Required")
    win.geometry("480x300")
    win.transient(parent)
    win.grab_set()
    ctk.CTkLabel(win, text=f"Confirm {mode.upper()} Scan",
                 font=("Segoe UI", 15, "bold")).pack(pady=(18, 6))
    ctk.CTkLabel(win, wraplength=420, justify="left",
                 text="Active verification sends test payloads to the target. "
                      "Only proceed if you own the target or hold written "
                      "permission to test it. All activity is audit-logged.").pack(pady=6, padx=18)
    var = tk.BooleanVar(value=False)
    ctk.CTkCheckBox(win, text="I own this target / have written authorization",
                    variable=var).pack(pady=10)

    def _ok():
        result["ok"] = bool(var.get())
        win.destroy()

    def _cancel():
        win.destroy()

    row = ctk.CTkFrame(win, fg_color="transparent")
    row.pack(pady=10)
    ctk.CTkButton(row, text="Cancel", width=120, fg_color="#3a4556",
                  command=_cancel).pack(side="left", padx=8)
    ctk.CTkButton(row, text=f"Start {mode.title()}", width=160,
                  fg_color="#d64545", hover_color="#a83232",
                  command=_ok).pack(side="left", padx=8)
    parent.wait_window(win)
    return result["ok"]
