"""Authorization / IDOR / BOLA analysis using two user-provided test accounts.

Compares responses for object IDs across account A and B. Never touches real users.
Active differential testing requires explicit user consent + two test sessions.
Passive mode flags IDOR-prone parameter names.
"""
from __future__ import annotations

import re

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import response_similarity, set_query_param, truncate

IDOR_PARAMS = {"id", "user_id", "userid", "account_id", "accountid", "document_id",
               "order_id", "orderid", "resource_id", "file_id", "invoice_id",
               "profile_id", "customer_id", "object_id", "uid"}


class AuthorizationModule(BaseModule):
    name = "authorization"
    description = "IDOR/BOLA differential analysis (two test accounts)"

    async def run(self, target, pages, context):
        cands = []
        for p in pages:
            for gp in p.get_params:
                if gp.lower() in IDOR_PARAMS:
                    cands.append((p.url, "GET", gp))
        for url, method, pr in cands[:100]:
            self.add_finding(
                name="IDOR-Prone Parameter", severity="Medium", confidence="Low",
                url=url, method=method, parameter=pr,
                evidence=f"Object-reference parameter '{pr}' may lack authorization checks",
                request_summary=f"{method} {url}", response_summary="name heuristic",
                description="Endpoints accepting object IDs must enforce per-object authorization.",
                impact="Horizontal/vertical access to other users' objects.",
                remediation="Server-side authorization on every object access; use indirect references.",
                cwe="CWE-639", owasp="A01:2021 - Broken Access Control",
                references=["https://owasp.org/API-Security/editions/2023/en/0x11-t10/"])
        if not self.active:
            return self.findings
        # Active differential test: needs two session cookies provided by user
        cookie_a = (context.get("session_a") or "").strip()
        cookie_b = (context.get("session_b") or "").strip()
        if not cookie_a or not cookie_b:
            self.log("IDOR differential test needs two test-account session cookies; skipping")
            return self.findings
        for url, method, pr in cands[:20]:
            if self.client.stopped:
                raise StopRequested("stopped")
            try:
                turl = set_query_param(url, pr, "1")
                ra = await self.client.get(turl, headers={"Cookie": cookie_a})
                rb = await self.client.get(turl, headers={"Cookie": cookie_b})
                self.params_tested += 2
                sim = response_similarity(ra.text or "", rb.text or "")
                # identical object content across two different accounts = suspicious
                if sim > 0.95 and len(ra.text or "") > 200 and ra.status_code == 200 and rb.status_code == 200:
                    self.add_finding(
                        name="Possible IDOR / BOLA (Identical Cross-Account Response)",
                        severity="High", confidence="Low",
                        url=turl, method="GET", parameter=pr,
                        evidence=f"Two different test sessions got near-identical responses (sim={sim:.2f})",
                        request_summary=f"GET {truncate(turl, 250)} with session A vs B",
                        response_summary=f"A={ra.status_code}/{len(ra.text or '')} B={rb.status_code}/{len(rb.text or '')}",
                        description="Same object ID returns same data for two different test accounts.",
                        impact="Possible missing object-level authorization.",
                        remediation="Verify manually with owned accounts, then enforce object-level checks.",
                        cwe="CWE-639", owasp="A01:2021 - Broken Access Control",
                        references=["https://owasp.org/API-Security/editions/2023/en/0x11-t10/"])
            except StopRequested:
                raise
            except Exception:
                continue
        return self.findings
