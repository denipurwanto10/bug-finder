"""TLS checks: version, certificate expiry, hostname match (passive handshake)."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from app.scanner.base import BaseModule


class TlsModule(BaseModule):
    name = "tls"
    description = "TLS version, certificate validity and hostname checks"

    async def run(self, target, pages, context):
        url = target.url if hasattr(target, "url") else str(target)
        parts = urlparse(url)
        if parts.scheme != "https":
            self.add_finding(
                name="Site Not Served Over HTTPS", severity="High", confidence="High",
                url=url, method="GET", parameter="(scheme)",
                evidence=f"scheme={parts.scheme or '(none)'}",
                request_summary=f"Target {url}", response_summary="scheme analysis",
                description="Traffic is unencrypted.",
                impact="Credential/session theft via network sniffing.",
                remediation="Serve everything over HTTPS with HSTS.",
                cwe="CWE-319", owasp="A02:2021 - Cryptographic Failures",
                references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"])
            return self.findings
        host = parts.hostname or ""
        port = parts.port or 443
        try:
            info = await self._handshake(host, port)
        except Exception as e:
            self.log(f"TLS handshake failed: {e}")
            return self.findings
        version = info.get("version", "")
        if "TLSv1.0" in version or "TLSv1.1" in version:
            self.add_finding(
                name=f"Deprecated TLS Version ({version})", severity="Medium", confidence="High",
                url=url, method="GET", parameter="(TLS)",
                evidence=f"negotiated={version}",
                request_summary=f"TLS handshake {host}:{port}", response_summary=f"version={version}",
                description="Old TLS versions have known weaknesses.",
                impact="Decryption/downgrade attacks.",
                remediation="Enable TLS 1.2+ only (prefer 1.3).",
                cwe="CWE-327", owasp="A02:2021 - Cryptographic Failures", references=[])
        exp = info.get("not_after")
        if exp:
            days = (exp - datetime.now(timezone.utc)).days
            if days < 0:
                self.add_finding(
                    name="TLS Certificate Expired", severity="High", confidence="High",
                    url=url, method="GET", parameter="(certificate)",
                    evidence=f"notAfter={exp.isoformat()}",
                    request_summary=f"TLS handshake {host}", response_summary="certificate expired",
                    description="Certificate is expired.", impact="Trust failure / MITM risk.",
                    remediation="Renew certificate; automate renewal.",
                    cwe="CWE-298", owasp="A02:2021", references=[])
            elif days < 30:
                self.add_finding(
                    name="TLS Certificate Expiring Soon", severity="Low", confidence="High",
                    url=url, method="GET", parameter="(certificate)",
                    evidence=f"expires in {days} days ({exp.date().isoformat()})",
                    request_summary=f"TLS handshake {host}", response_summary=f"days_left={days}",
                    description="Certificate expires soon.", impact="Outage risk.",
                    remediation="Renew before expiry.", cwe="CWE-298", owasp="A02:2021", references=[])
        if info.get("hostname_mismatch"):
            self.add_finding(
                name="TLS Hostname Mismatch", severity="High", confidence="High",
                url=url, method="GET", parameter="(certificate)",
                evidence=f"cert CN/SAN does not cover {host}",
                request_summary=f"TLS handshake {host}", response_summary="hostname mismatch",
                description="Certificate identity does not match host.",
                impact="MITM / trust failure.", remediation="Issue cert for the correct hostname.",
                cwe="CWE-297", owasp="A02:2021", references=[])
        return self.findings

    async def _handshake(self, host, port):
        import asyncio
        def _do():
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                try:
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        cert = ss.getpeercert()
                        return {"version": ss.version() or "", "cert": cert,
                                "hostname_mismatch": False, "not_after": self._parse_exp(cert)}
                except ssl.CertificateError:
                    with ctx.wrap_socket(sock, server_hostname=host) as ss:
                        return {"version": ss.version() or "", "cert": ss.getpeercert(),
                                "hostname_mismatch": True, "not_after": None}
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _do)

    def _parse_exp(self, cert):
        try:
            na = cert.get("notAfter")
            if not na:
                return None
            return datetime.strptime(na, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except Exception:
            return None
