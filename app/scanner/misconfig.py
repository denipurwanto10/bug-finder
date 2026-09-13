"""Security misconfiguration checks: exposed files, git, backups, docs, methods."""
from __future__ import annotations

from urllib.parse import urljoin

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested

PATHS = [
    ("/.env", "Exposed .env File", "Critical", ".env with secrets?", "Remove; rotate any exposed secrets."),
    ("/.git/HEAD", "Exposed Git Repository", "High", "Git internals readable", "Block .git at server/CDN."),
    ("/.git/config", "Exposed Git Config", "High", "Git config readable", "Block .git."),
    ("/server-status", "Exposed Server Status", "Medium", "mod_status public", "Restrict to localhost."),
    ("/phpinfo.php", "Exposed phpinfo()", "Medium", "PHP config disclosure", "Remove file."),
    ("/.DS_Store", "Exposed .DS_Store", "Low", "macOS metadata", "Block dotfiles."),
    ("/backup.zip", "Backup File Exposed", "High", "Archive downloadable", "Remove backups from webroot."),
    ("/backup.sql", "Backup File Exposed", "High", "DB dump downloadable", "Remove; rotate creds if leaked."),
    ("/wp-config.php.bak", "Backup File Exposed", "High", "Config backup", "Remove backups."),
    ("/config.php.bak", "Backup File Exposed", "High", "Config backup", "Remove backups."),
    ("/swagger.json", "Exposed API Documentation", "Low", "Swagger spec public", "Gate docs behind auth."),
    ("/api-docs", "Exposed API Documentation", "Low", "Docs UI public", "Gate docs behind auth."),
    ("/openapi.json", "Exposed API Documentation", "Low", "OpenAPI spec public", "Gate docs behind auth."),
    ("/graphql", "GraphQL Endpoint Exposed", "Informational", "GraphQL reachable", "Auth + introspection off in prod."),
    ("/admin", "Exposed Admin Interface", "Informational", "Admin panel reachable", "Restrict + MFA + IP allow-list."),
    ("/wp-admin", "Exposed Admin Interface", "Informational", "wp-admin reachable", "Restrict + MFA."),
    ("/server-info", "Exposed Server Info", "Low", "server-info public", "Disable."),
    ("/.well-known/security.txt", "Missing security.txt", "Informational", "no contact file", "Add security.txt (informational)."),
]


class MisconfigModule(BaseModule):
    name = "misconfig"
    description = "Exposed files, debug, listing, methods, docs"

    async def run(self, target, pages, context):
        base = target.url if hasattr(target, "url") else str(target)
        try:
            _home = await self.client.get(base)
            homepage_body = ((_home.text or "")[:3000]).strip()
        except Exception:
            homepage_body = ""
        for suffix, title, sev, desc, fix in PATHS:
            if self.client.stopped:
                raise StopRequested("stopped")
            url = urljoin(base + "/", suffix.lstrip("/"))
            if not self.client.sync_check_scope(url):
                continue
            is_negative = suffix == "/.well-known/security.txt"
            try:
                r = await self.client.get(url)
            except StopRequested:
                raise
            except Exception:
                continue
            body = (r.text or "")[:3000]
            if is_negative:
                if r.status_code == 404:
                    self.add_finding(
                        name=title, severity="Informational", confidence="High",
                        url=url, method="GET", parameter="(file)",
                        evidence="404 for security.txt",
                        request_summary=f"GET {url}", response_summary="status=404",
                        description="No security.txt contact file. Optional hardening.",
                        impact="Slower responsible disclosure.",
                        remediation="Publish /.well-known/security.txt with contact.",
                        cwe="CWE-200", owasp="A05:2021 - Security Misconfiguration", references=[])
                continue
            if r.status_code == 200 and len(body) > 20 and "not found" not in body.lower()[:200]:
                # sanity: .env must look like KEY=VALUE, git HEAD must say ref:
                if suffix == "/.env" and "=" not in body:
                    continue
                if suffix == "/.git/HEAD" and "ref:" not in body.lower():
                    continue
                if suffix == "/.git/config" and "[core]" not in body.lower():
                    continue
                if suffix in ("/backup.zip",) and "pk\x03\x04" not in body[:4]:
                    continue
                if suffix in ("/backup.sql",) and not any(
                        k in body.lower() for k in ("create table", "insert into", "mysqldump", "-- ")):
                    continue
                if suffix.endswith(".bak") and len(body) < 100:
                    continue
                # generic FP guard: body identical to homepage (catch-all servers)
                if body.strip() == homepage_body:
                    continue
                self.add_finding(
                    name=title, severity=sev, confidence="Medium",
                    url=url, method="GET", parameter="(file)",
                    evidence=f"HTTP 200, {len(body)} bytes",
                    request_summary=f"GET {url}", response_summary=f"status=200 len={len(body)}",
                    description=desc, impact="Information disclosure / config leak.",
                    remediation=fix, cwe="CWE-538",
                    owasp="A05:2021 - Security Misconfiguration",
                    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"])
        # directory listing on main pages
        for p in pages[:20]:
            if "Index of /" in (getattr(p, "title", "") or ""):
                self.add_finding(
                    name="Directory Listing Enabled", severity="Low", confidence="High",
                    url=p.url, method="GET", parameter="(listing)",
                    evidence="Title contains 'Index of /'",
                    request_summary=f"GET {p.url}", response_summary="directory listing",
                    description="Directory listing exposes filenames.",
                    impact="Aids targeted attacks.", remediation="Disable autoindex.",
                    cwe="CWE-548", owasp="A05:2021 - Security Misconfiguration", references=[])
        # TRACE method
        try:
            base_url = base
            r = await self.client.request("TRACE", base_url)
            if r.status_code in (200,):
                self.add_finding(
                    name="HTTP TRACE Enabled (XST Risk)", severity="Low", confidence="Medium",
                    url=base_url, method="TRACE", parameter="(method)",
                    evidence=f"TRACE -> {r.status_code}",
                    request_summary=f"TRACE {base_url}", response_summary=f"status={r.status_code}",
                    description="TRACE echoes requests; legacy XST risk.",
                    impact="Cookie theft in old browsers.", remediation="Disable TRACE/TRACK.",
                    cwe="CWE-749", owasp="A05:2021", references=[])
        except StopRequested:
            raise
        except Exception:
            pass
        return self.findings
