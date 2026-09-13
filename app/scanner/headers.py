"""Security headers + cookie flags + CORS checks (passive)."""
from __future__ import annotations

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested

HEADER_CHECKS = [
    ("content-security-policy", "Missing Content-Security-Policy", "Medium",
     "No CSP: XSS impact is higher.", "Deploy a strict CSP.", "CWE-693"),
    ("strict-transport-security", "Missing HSTS", "Low",
     "No HSTS enforcement.", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.", "CWE-319"),
    ("x-frame-options", "Missing X-Frame-Options", "Low",
     "Clickjacking risk.", "Set X-Frame-Options: DENY/SAMEORIGIN or frame-ancestors in CSP.", "CWE-1021"),
    ("x-content-type-options", "Missing X-Content-Type-Options", "Low",
     "MIME-sniffing risk.", "Set X-Content-Type-Options: nosniff.", "CWE-693"),
    ("referrer-policy", "Missing Referrer-Policy", "Informational",
     "Referrer leakage possible.", "Set Referrer-Policy: strict-origin-when-cross-origin.", "CWE-200"),
    ("permissions-policy", "Missing Permissions-Policy", "Informational",
     "Browser features unrestricted.", "Set Permissions-Policy to least privilege.", "CWE-693"),
]


class HeadersModule(BaseModule):
    name = "headers"
    description = "Security headers, cookie flags, CORS review"

    async def run(self, target, pages, context):
        urls = [target.url if hasattr(target, "url") else str(target)]
        urls += [p.url for p in pages[:10]]
        seen, uniq = set(), []
        for u in urls:
            if u not in seen:
                seen.add(u); uniq.append(u)
        main = uniq[0] if uniq else ""
        reported: set[str] = set()  # header reported once globally
        for url in uniq:
            if self.client.stopped:
                raise StopRequested("stopped")
            try:
                r = await self.client.get(url)
            except StopRequested:
                raise
            except Exception:
                continue
            low = {k.lower(): v for k, v in r.headers.items()}
            for key, title, sev, desc, fix, cwe in HEADER_CHECKS:
                if key not in low:
                    # only report missing headers on the main target to reduce noise
                    if url != main and sev == "Informational":
                        continue
                    if title in reported:
                        continue
                    reported.add(title)
                    self.add_finding(
                        name=title, severity=sev, confidence="High",
                        url=url, method="GET", parameter=f"(header: {key})",
                        evidence=f"{key} not present (status={r.status_code})",
                        request_summary=f"GET {url}", response_summary=f"status={r.status_code}",
                        description=desc, impact=desc, remediation=fix, cwe=cwe,
                        owasp="A05:2021 - Security Misconfiguration",
                        references=["https://owasp.org/www-project-secure-headers/"])
            acao = low.get("access-control-allow-origin", "")
            acac = low.get("access-control-allow-credentials", "")
            if acao == "*" and acac.lower() == "true":
                self.add_finding(
                    name="CORS Wildcard With Credentials", severity="High", confidence="High",
                    url=url, method="GET", parameter="Origin",
                    evidence="Access-Control-Allow-Origin: * + Allow-Credentials: true",
                    request_summary=f"GET {url}", response_summary=f"status={r.status_code}",
                    description="Any origin can make credentialed reads.",
                    impact="Cross-origin theft of authenticated responses.",
                    remediation="Reflect only trusted origins; use Vary: Origin.",
                    cwe="CWE-942", owasp="A01:2021 - Broken Access Control",
                    references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"])
            server = r.headers.get("server", "") + " " + r.headers.get("x-powered-by", "")
            if server.strip() and url == main:
                self.add_finding(
                    name="Server Version Disclosure", severity="Informational", confidence="High",
                    url=url, method="GET", parameter="(Server header)",
                    evidence=f"Server: {server.strip()[:150]}",
                    request_summary=f"GET {url}", response_summary=f"status={r.status_code}",
                    description="Server banner reveals software/version.",
                    impact="Aids targeted exploitation.",
                    remediation="Minimize Server/X-Powered-By banners.",
                    cwe="CWE-200", owasp="A05:2021 - Security Misconfiguration", references=[])
        return self.findings
