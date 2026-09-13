"""Technology fingerprinting + version matching against a small built-in CVE dataset."""
from __future__ import annotations

import json
import re
from pathlib import Path

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import truncate

VULN_DB = Path(__file__).resolve().parent.parent / "payloads" / "cve_sample.json"

FRAMEWORK_SIGS = [
    (re.compile(r"wp-content|wp-includes|/wp-json/", re.I), "WordPress", None),
    (re.compile(r"Joomla", re.I), "Joomla", None),
    (re.compile(r"drupal", re.I), "Drupal", None),
    (re.compile(r"_next/static", re.I), "Next.js", None),
    (re.compile(r"__NEXT_DATA__", re.I), "Next.js", None),
    (re.compile(r"ng-version|angular", re.I), "Angular", None),
    (re.compile(r"react", re.I), "React", None),
    (re.compile(r"vue(\.min)?\.js|__VUE__", re.I), "Vue.js", None),
    (re.compile(r"laravel", re.I), "Laravel", None),
    (re.compile(r"django|csrfmiddlewaretoken", re.I), "Django", None),
    (re.compile(r"flask|werkzeug", re.I), "Flask", None),
    (re.compile(r"rails|ruby", re.I), "Ruby on Rails", None),
    (re.compile(r"asp\.net|__VIEWSTATE", re.I), "ASP.NET", None),
    (re.compile(r"php", re.I), "PHP", None),
]


class DependenciesModule(BaseModule):
    name = "dependencies"
    description = "Framework/library/CMS detection + CVE matching"

    def _load_db(self):
        try:
            return json.loads(VULN_DB.read_text(encoding="utf-8"))
        except Exception:
            return []

    async def run(self, target, pages, context):
        detected: dict[str, dict] = {}
        for p in pages[:40]:
            try:
                r = await self.client.get(p.url)
            except StopRequested:
                raise
            except Exception:
                continue
            text = (r.text or "")[:60000]
            headers = " ".join(r.headers.values())
            blob = text + "\n" + headers
            for rx, tech, _ in FRAMEWORK_SIGS:
                if rx.search(blob) and tech not in detected:
                    ver = self._extract_version(tech, blob)
                    detected[tech] = {"version": ver, "url": p.url}
            # JS library versions from script src
            for src in p.js_files[:20]:
                m = re.search(r"(jquery|bootstrap|lodash|moment|axios|react|vue|angular)[.-](\d+\.\d+(?:\.\d+)?)", src, re.I)
                if m:
                    lib, ver = m.group(1).title(), m.group(2)
                    if lib not in detected:
                        detected[lib] = {"version": ver, "url": src}
        db = self._load_db()
        for tech, info in detected.items():
            ver = info.get("version") or ""
            self.add_finding(
                name=f"Technology Detected: {tech} {ver}".strip(), severity="Informational",
                confidence="Medium" if ver else "Low",
                url=info.get("url", ""), method="GET", parameter="(fingerprint)",
                evidence=f"{tech} {ver or '(version unknown)'}",
                request_summary="GET (fingerprint)", response_summary="banner/content analysis",
                description=f"Detected {tech}. Keep it patched and hide version banners.",
                impact="Outdated components are a leading breach cause.",
                remediation="Update to supported releases; remove version banners.",
                cwe="CWE-1104", owasp="A06:2021 - Vulnerable Components",
                references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"])
            for entry in db:
                if entry.get("package", "").lower() == tech.lower() and ver:
                    if self._version_in_range(ver, entry.get("affected", "")):
                        self.add_finding(
                            name=f"{tech} {ver} — {entry.get('cve')}", severity=entry.get("severity", "Medium"),
                            confidence="Medium", url=info.get("url", ""), method="GET",
                            parameter="(version)",
                            evidence=f"{tech} {ver} in affected range {entry.get('affected')}: {truncate(entry.get('summary', ''), 200)}",
                            request_summary="version match vs local CVE sample DB",
                            response_summary=f"CVE={entry.get('cve')}",
                            description=entry.get("summary", ""),
                            impact=f"See {entry.get('cve')}.",
                            remediation=entry.get("remediation", "Upgrade to a fixed release."),
                            cwe="CWE-1104", owasp="A06:2021 - Vulnerable Components",
                            references=[f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={entry.get('cve')}"])
        if not detected:
            self.log("No technologies fingerprinted")
        return self.findings

    def _extract_version(self, tech, blob):
        pats = {
            "WordPress": [r"wp-includes.*?ver=([\d.]+)", r"WordPress\s*([\d.]+)"],
            "Joomla": [r"Joomla!?[\s_]*([\d.]+)"],
            "Drupal": [r"Drupal\s*([\d.]+)"],
            "jQuery": [r"jquery[.-]([\d.]+)"],
        }
        for rx in pats.get(tech, [re.compile(re.escape(tech) + r"\s*([\d][\d.]*)", re.I)]):
            m = re.search(rx, blob, re.I) if isinstance(rx, str) else rx.search(blob)
            if m:
                return m.group(1)
        return ""

    def _version_in_range(self, ver, affected: str) -> bool:
        # affected like "<5.9, >=4.0" or "<2.0"
        try:
            from packaging.version import Version
            v = Version(ver)
            for part in affected.split(","):
                part = part.strip()
                if part.startswith("<=") and not (v <= Version(part[2:].strip())):
                    return False
                elif part.startswith(">=") and not (v >= Version(part[2:].strip())):
                    return False
                elif part.startswith("<") and not (v < Version(part[1:].strip())):
                    return False
                elif part.startswith(">") and not (v > Version(part[1:].strip())):
                    return False
            return True
        except Exception:
            return False
