"""Report generation: HTML / JSON / CSV / PDF."""
from __future__ import annotations

import csv
import html as htmlmod
import json
from datetime import datetime
from pathlib import Path

from app.utils.helpers import mask_secrets, severity_counts


def _norm_findings(findings) -> list[dict]:
    out = []
    for f in findings:
        d = f.to_dict() if hasattr(f, "to_dict") else dict(f)
        out.append(d)
    return out


def build_summary(target, mode, score, findings, stats) -> dict:
    counts = severity_counts(findings if findings and isinstance(findings[0], dict) else
                             [f.to_dict() if hasattr(f, "to_dict") else f for f in findings])
    return {"target": target, "mode": mode, "security_score": score,
            "severity_counts": counts, "total": len(findings), "stats": stats}


def export_json(path: str, target, scope, mode, score, findings, stats, timeline=None) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    data = {
        "tool": "WebGuard Pro 1.0.0", "generated_at": datetime.now().isoformat(timespec="seconds"),
        "target": target, "scope": scope, "mode": mode, "methodology": METHODOLOGY,
        "security_score": score, "summary": build_summary(target, mode, score, findings, {}),
        "stats": stats, "timeline": timeline or [],
        "findings": [mask_finding(f) for f in _norm_findings(findings)],
    }
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def mask_finding(d: dict) -> dict:
    d = dict(d)
    for k in ("evidence", "request_summary", "response_summary"):
        d[k] = mask_secrets(str(d.get(k, "")))
    return d


METHODOLOGY = (
    "1) Scope validation & authorization confirmation. 2) Rate-limited crawl (robots/sitemap, "
    "forms, params, JS, API hints). 3) Passive analysis (headers, TLS, JWT, dependencies, "
    "misconfiguration). 4) Controlled active verification with safe, non-destructive payloads "
    "only (XSS canary, SQLi error/boolean/timing indicators, sleep probes, harmless uploads, "
    "user-owned SSRF callback). No dumping, no destructive commands, no credential use."
)


def export_csv(path: str, findings) -> str:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    rows = _norm_findings(findings)
    fields = ["name", "severity", "confidence", "cwe", "owasp", "url", "method",
              "parameter", "evidence", "remediation", "module"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(mask_finding(r))
    return path


def export_html(path: str, target, scope, mode, score, findings, stats, timeline=None) -> str:
    rows = [mask_finding(f) for f in _norm_findings(findings)]
    counts = severity_counts(rows)
    color = {"Critical": "#d64545", "High": "#e07b39", "Medium": "#d9a441",
             "Low": "#4f9cf0", "Informational": "#8a93a3"}
    def esc(x): return htmlmod.escape(str(x or ""))
    cards = "".join(
        f"<div class='sev' style='border-left:5px solid {color.get(k,'#888')}'><b>{k}</b><span>{v}</span></div>"
        for k, v in counts.items())
    items = ""
    for i, f in enumerate(rows, 1):
        items += f"""<section class='finding'>
        <h3>#{i} {esc(f.get('name'))} <span class='badge' style='background:{color.get(f.get('severity'),'#888')}'>{esc(f.get('severity'))}</span>
        <span class='conf'>confidence: {esc(f.get('confidence'))}</span></h3>
        <table>
        <tr><th>CWE</th><td>{esc(f.get('cwe'))}</td><th>OWASP</th><td>{esc(f.get('owasp'))}</td></tr>
        <tr><th>URL</th><td colspan='3'><code>{esc(f.get('url'))}</code></td></tr>
        <tr><th>Method</th><td>{esc(f.get('method'))}</td><th>Parameter</th><td><code>{esc(f.get('parameter'))}</code></td></tr>
        <tr><th>Evidence</th><td colspan='3'><pre>{esc(f.get('evidence'))}</pre></td></tr>
        <tr><th>Request</th><td colspan='3'><pre>{esc(f.get('request_summary'))}</pre></td></tr>
        <tr><th>Response</th><td colspan='3'><pre>{esc(f.get('response_summary'))}</pre></td></tr>
        <tr><th>Description</th><td colspan='3'>{esc(f.get('description'))}</td></tr>
        <tr><th>Impact</th><td colspan='3'>{esc(f.get('impact'))}</td></tr>
        <tr><th>Remediation</th><td colspan='3'>{esc(f.get('remediation'))}</td></tr>
        </table></section>"""
    tl = ""
    for t in (timeline or []):
        tl += f"<li>{esc(t)}</li>"
    doc = f"""<!DOCTYPE html><html><head><meta charset='utf-8'>
    <title>WebGuard Pro Report — {esc(target)}</title>
    <style>body{{font-family:Segoe UI,Arial,sans-serif;background:#0f141b;color:#dfe6ef;margin:0}}
    header{{background:#151d27;padding:24px 32px;border-bottom:1px solid #26313f}}
    main{{padding:24px 32px;max-width:1100px}} .sev{{display:inline-block;background:#151d27;
    padding:10px 18px;margin:6px;border-radius:6px}} .sev span{{font-size:22px;margin-left:10px}}
    .finding{{background:#151d27;border:1px solid #26313f;border-radius:8px;padding:16px;margin:14px 0}}
    table{{width:100%;border-collapse:collapse}} th{{text-align:left;color:#8a93a3;width:110px;
    padding:6px;vertical-align:top}} td{{padding:6px}} pre{{white-space:pre-wrap;background:#0b1016;
    padding:8px;border-radius:6px}} .badge{{color:#fff;padding:2px 10px;border-radius:10px;font-size:12px}}
    .conf{{color:#8a93a3;font-size:12px;margin-left:8px}} code{{color:#7fd0ff}}</style></head>
    <body><header><h1>WebGuard Pro — Security Assessment Report</h1>
    <p>Target: <b>{esc(target)}</b> | Mode: {esc(mode)} | Score: <b>{score}/100</b></p>
    <p>Scope: {esc(', '.join(scope or []))}</p></header><main>
    <h2>Executive Summary</h2>
    <p>This authorized assessment scanned <b>{esc(str(stats.get('pages_scanned', 0)))}</b> pages with
    <b>{esc(str(stats.get('requests_sent', 0)))}</b> rate-limited requests, finding
    <b>{len(rows)}</b> issues. Overall security score: <b>{score}/100</b>.</p>
    <div>{cards}</div>
    <h2>Scope</h2><p>{esc(', '.join(scope or []))}</p>
    <h2>Methodology</h2><p>{esc(METHODOLOGY)}</p>
    <h2>Vulnerability Summary</h2><div>{cards}</div>
    <h2>Detailed Findings</h2>{items or '<p>No findings.</p>'}
    <h2>Scan Timeline</h2><ul>{tl or '<li>n/a</li>'}</ul>
    <h2>Technical Appendix</h2><p>Stats: <code>{esc(json.dumps(stats))}</code></p>
    <p><i>Secrets masked. Generated by WebGuard Pro (authorized testing only).</i></p>
    </main></body></html>"""
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(doc, encoding="utf-8")
    return path


def export_pdf(path: str, target, scope, mode, score, findings, stats, timeline=None) -> str:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib import colors
    rows = [mask_finding(f) for f in _norm_findings(findings)]
    counts = severity_counts(rows)
    styles = getSampleStyleSheet()
    story = [Paragraph("WebGuard Pro — Security Assessment Report", styles["Title"]),
             Paragraph(f"Target: {target} | Mode: {mode} | Score: {score}/100", styles["Normal"]),
             Paragraph(f"Scope: {', '.join(scope or [])}", styles["Normal"]),
             Spacer(1, 6 * mm),
             Paragraph("Executive Summary", styles["Heading2"]),
             Paragraph(f"Pages: {stats.get('pages_scanned', 0)}, Requests: {stats.get('requests_sent', 0)}, "
                       f"Findings: {len(rows)}. Severity: {counts}.", styles["Normal"]),
             Spacer(1, 4 * mm),
             Paragraph("Methodology", styles["Heading2"]),
             Paragraph(METHODOLOGY, styles["Normal"]),
             Spacer(1, 4 * mm),
             Paragraph("Detailed Findings", styles["Heading2"])]
    for i, f in enumerate(rows, 1):
        story.append(Paragraph(f"#{i} [{f.get('severity')}] {f.get('name')}", styles["Heading3"]))
        t = Table([[k, str(f.get(k, ""))[:800]] for k in
                   ("cwe", "owasp", "url", "method", "parameter", "confidence",
                    "evidence", "description", "impact", "remediation")],
                  colWidths=[28 * mm, 150 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8edf3")),
                               ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
        story.append(Spacer(1, 3 * mm))
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(path, pagesize=A4).build(story)
    return path
