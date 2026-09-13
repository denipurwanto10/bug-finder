"""File upload security: detect weak validation using harmless test files only."""
from __future__ import annotations

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import truncate

HARMLESS_TEXT = b"WebGuardPro harmless upload test - not executable.\n"
# Harmless names that reveal weak validation WITHOUT uploading malware/webshells
TEST_NAMES = [
    "webguard_test.txt",
    "webguard_test.txt.exe",   # double extension probe (sent as .txt content)
    "webguard_test.phtml.txt",
    "../webguard_test.txt",    # filename traversal probe
]


class UploadModule(BaseModule):
    name = "upload"
    description = "Unrestricted upload / MIME / traversal checks (harmless files)"

    async def run(self, target, pages, context):
        forms = []
        for p in pages:
            for f in p.forms:
                types = [(i.get("type") or "").lower() for i in f["inputs"]]
                if "file" in types:
                    forms.append(f)
        if not forms:
            self.log("No file-upload forms discovered")
            return self.findings
        for f in forms[:10]:
            self.add_finding(
                name="File Upload Endpoint Found", severity="Informational", confidence="High",
                url=f["action"], method=f["method"], parameter="(file input)",
                evidence=f"Upload form at {f['action']} method={f['method']}",
                request_summary=f"{f['method']} {f['action']}",
                response_summary="form discovered by crawler",
                description="Review upload validation: extension allow-list, MIME sniffing, size, storage, execution.",
                impact="Weak upload validation can lead to stored XSS or RCE.",
                remediation="Allow-list extensions; verify magic bytes; store outside webroot; randomize names; no exec.",
                cwe="CWE-434", owasp="A04:2021 - Insecure Design",
                references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"])
        if not self.active:
            return self.findings
        for f in forms[:5]:
            if self.client.stopped:
                raise StopRequested("stopped")
            await self._probe(f)
        return self.findings

    async def _probe(self, form):
        # Send a HARMLESS .txt file; observe acceptance behavior.
        try:
            files = {"file": ("webguard_test.txt", HARMLESS_TEXT, "text/plain")}
            r = await self.client.post(form["action"], files=files)
            self.params_tested += 1
            body = (r.text or "").lower()
            if r.status_code in (200, 201) and any(k in body for k in ("upload", "success", "stored", "file")):
                self.add_finding(
                    name="File Upload Accepted (Review Validation)", severity="Medium", confidence="Low",
                    url=form["action"], method="POST", parameter="file",
                    evidence=f"Harmless .txt accepted: status={r.status_code}",
                    request_summary=f"POST {form['action']} (harmless webguard_test.txt)",
                    response_summary=f"status={r.status_code} len={len(r.text or '')}",
                    description="Upload endpoint accepts files; verify extension/MIME/size enforcement manually.",
                    impact="If executable types are accepted, stored XSS/RCE may follow.",
                    remediation="Enforce allow-list + content-type verification + random filenames.",
                    cwe="CWE-434", owasp="A04:2021 - Insecure Design",
                    references=["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload"])
        except StopRequested:
            raise
        except Exception as e:
            self.log(f"upload probe failed: {e}")
        # MIME mismatch probe: .txt content labeled image/png
        try:
            files = {"file": ("webguard_mime.txt", HARMLESS_TEXT, "image/png")}
            r = await self.client.post(form["action"], files=files)
            self.params_tested += 1
            if r.status_code in (200, 201):
                self.add_finding(
                    name="Upload MIME Validation Weakness (Indicator)", severity="Low", confidence="Low",
                    url=form["action"], method="POST", parameter="file",
                    evidence=f"Mismatched MIME (txt-as-png) accepted: status={r.status_code}",
                    request_summary=f"POST {form['action']} (MIME mismatch probe)",
                    response_summary=f"status={r.status_code}",
                    description="Server accepted a file whose declared MIME contradicts its extension/content.",
                    impact="MIME-only validation can be bypassed.",
                    remediation="Validate magic bytes server-side, not client MIME.",
                    cwe="CWE-434", owasp="A04:2021 - Insecure Design", references=[])
        except StopRequested:
            raise
        except Exception:
            pass
