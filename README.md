# WebGuard Pro — Web Vulnerability Scanner & Authorized Pentest Toolkit

Desktop app (Python 3.12+, CustomTkinter) for **authorized** security auditing of websites,
APIs, and web apps you own or have written permission to test.

## Features (26-spec coverage)

- Target + scope enforcement (out-of-scope requests blocked, audit-logged)
- Modes: Passive / Active / Authorized Pentest (confirmation modal for active)
- Async crawler: pages, endpoints, GET/POST params, forms, JS files, API hints,
  robots.txt + sitemap.xml, depth/request caps, concurrent workers, rate limit
- Scanners: XSS (reflected/canary + DOM sinks), SQLi (error/boolean/controlled
  time/UNION indicators), command injection (non-destructive canary/sleep/error),
  path traversal/LFI (safe files only, no credentials), SSRF (risky-param detection
  + **your own callback** verification), auth testing (test accounts only,
  rate-limited), IDOR/BOLA (two test sessions differential), upload (harmless files),
  API/GraphQL, JWT analyzer, security misconfiguration, dependency/CVE sample DB,
  security headers + TLS
- Safety: RPS cap, max requests, timeout, depth, workers, duration limit, STOP SCAN
- Dashboard: 0–100 score, severity cards, progress, recent findings, stats, audit log
- Findings: name, CWE, OWASP, severity, confidence, URL, method, param, evidence,
  request/response summaries, description, impact, remediation, refs (secrets masked)
- Reports: HTML / PDF / JSON / CSV (summary, scope, methodology, score, findings,
  evidence, remediation, timeline, appendix)
- History: SQLite (view, delete, compare, export)
- Audit log: scan start/stop/complete, modules, counts, findings, errors — secrets redacted

## Safety / ethics

Authorized testing only. Active modules use **safe verification payloads**: no malware,
no persistence, no destructive commands, no DB dumping, no credential/token theft,
no credential stuffing, no server takeover automation. Destructive techniques are
replaced by canary/timing/error indicators plus remediation guidance.

## Install (mesin ini: Python 3.13, tanpa venv)

`pip` di Python 3.13 mesin ini macet, jadi dependensi sudah dipasang ke folder
`libs/` via `install_wheels.py` (stdlib saja, tanpa pip). Untuk menambah paket:

```powershell
$PY = "C:\Users\M S I\AppData\Local\Programs\Python\Python313\python.exe"
& $PY install_wheels.py
```

Di mesin normal (pip sehat), cara standar tetap berlaku:

```bash
pip install -r requirements.txt
```

Requires Python 3.12+.

## Cara menjalankan (Windows PowerShell)

Semua perintah di bawah memakai Python 3.13 dan `PYTHONPATH=libs`
(agar `bs4`, `customtkinter`, `dnspython`, `reportlab` ketemu).

**1. Jalankan WebGuard Pro (GUI) — target default sudah publik:**

```powershell
cd C:\Website\bug-finder
$env:PYTHONPATH = "C:\Website\bug-finder\libs"
& "C:\Users\M S I\AppData\Local\Programs\Python\Python313\python.exe" app/main.py
```

GUI langsung terisi target default `https://portofolio-fajar-cs.vercel.app/`
(scope `portofolio-fajar-cs.vercel.app`) di halaman New Scan, Pentest, dan API Scanner.

**2. Lakukan scan pertama (di GUI):**

1. Buka halaman **New Scan** (target/scope sudah terisi URL publik).
2. Mode **Passive** → START SCAN. Tunggu selesai, lihat skor di **Dashboard**.
3. Ulangi dengan mode **Active** (centang persetujuan) untuk verifikasi terkontrol.
4. Lihat detail di **Vulnerabilities** (klik 2x), export via **Reports**, riwayat di **History**.

> Jangan scan situs yang bukan milikmu / tanpa izin tertulis.

**Lampiran opsional — demo offline (localhost):** kalau ingin latihan tanpa internet,
jalankan `test_target.py` di terminal terpisah lalu isi target `http://127.0.0.1:8765`
scope `127.0.0.1` secara manual.

Try: passive scan first, then active scan (confirm ownership), then Authorized Pentest.
Export a report from Reports view. History view stores every scan in `webguard.db`.

Other practice targets you run yourself: OWASP Juice Shop via Docker
(`docker run -p 3000:3000 bkimminich/juice-shop`), then scan your own instance.

## Layout

```
app/
├── main.py            # entry point
├── ui/                # CustomTkinter shell: app, dashboard, scan, vulns, api,
│                      # pentest, targets, history, reports, settings, widgets, theme
├── scanner/           # engine, crawler, http_client, base + 14 modules
├── database/db.py     # SQLite history
├── reports/generator.py  # HTML/PDF/JSON/CSV
├── payloads/cve_sample.json
├── utils/             # models, scope guard, audit logger, helpers
└── config/settings.py
test_target.py         # vulnerable local demo (127.0.0.1 ONLY)
requirements.txt
README.md
```

## Headless smoke test (no GUI, target publik)

```powershell
cd C:\Website\bug-finder
$env:PYTHONPATH = "C:\Website\bug-finder\libs"
& "C:\Users\M S I\AppData\Local\Programs\Python\Python313\python.exe" -c "
import asyncio, sys; sys.path.insert(0, '.')
from app.config.settings import AppConfig, DEFAULT_TARGET, DEFAULT_SCOPE
from app.scanner.engine import ScanEngine
from app.utils.models import Target
async def main():
    eng = ScanEngine(config=AppConfig())
    res = await eng.run_scan(Target(url=DEFAULT_TARGET, scope=list(DEFAULT_SCOPE)), mode='passive')
    print('score', res.security_score, 'findings', len(res.findings))
asyncio.run(main())"
```
