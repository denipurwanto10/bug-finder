"""SSRF scanner: detect risky params, verify only via user-owned callback endpoint."""
from __future__ import annotations

from urllib.parse import urlparse

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import set_query_param, truncate

SSRF_PARAMS = {"url", "target", "redirect", "callback", "webhook", "image",
               "fetch", "uri", "link", "src", "feed", "file", "path", "next",
               "continue", "dest", "destination", "u", "endpoint", "webhook_url",
               "callback_url", "redirect_uri"}


class SsrfModule(BaseModule):
    name = "ssrf"
    description = "SSRF-prone parameter detection (controlled callback only)"

    async def run(self, target, pages, context):
        callback = (context.get("ssrf_callback") or "").strip()
        cands = []
        for p in pages:
            params = list(p.get_params)
            for f in p.forms:
                names = [i["name"] for i in f["inputs"] if i["name"]]
                if names:
                    params.extend([(f["action"], f["method"], n) for n in names])
            for gp in p.get_params:
                cands.append((p.url, "GET", gp, None))
            for item in params:
                if isinstance(item, tuple):
                    cands.append(item)
        # forms fallback
        for p in pages:
            for f in p.forms:
                for i in f["inputs"]:
                    if i["name"] and (f["action"], f["method"], i["name"]) not in [(c[0], c[1], c[2]) for c in cands]:
                        cands.append((f["action"], f["method"], i["name"]))

        risky = [(u, m, pr) for (u, m, pr) in cands if pr.lower() in SSRF_PARAMS]
        # flag risky params even in passive mode
        for url, method, pr in risky[:200]:
            self.add_finding(
                name="SSRF-Prone Parameter", severity="Medium", confidence="Low",
                url=url, method=method, parameter=pr,
                evidence=f"Parameter name '{pr}' commonly used for outbound fetching",
                request_summary=f"{method} {url} param={pr}",
                response_summary="parameter-name heuristic (no outbound request made)",
                description="Parameter name suggests the server may fetch a user-supplied URL.",
                impact="SSRF can reach internal services and cloud metadata.",
                remediation="Allow-list outbound hosts; block private IP ranges; require auth for fetch features.",
                cwe="CWE-918", owasp="A10:2021 - SSRF",
                references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"])
        if not self.active or not callback:
            return self.findings
        # Active verification ONLY against the user-provided callback (their own endpoint)
        if not self.client.sync_check_scope(callback):
            self.log("SSRF callback outside scope; skipping active verification")
            return self.findings
        for url, method, pr in risky[:50]:
            if self.client.stopped:
                raise StopRequested("stopped")
            try:
                if method == "GET":
                    turl = set_query_param(url, pr, callback)
                    r = await self.client.get(turl)
                    req = f"GET {truncate(turl, 300)}"
                else:
                    r = await self.client.post(url, data={pr: callback})
                    req = f"POST {url} param={pr} -> callback"
                self.params_tested += 1
            except StopRequested:
                raise
            except Exception:
                continue
            self.add_finding(
                name="SSRF Verification Sent (Check Callback)", severity="Medium", confidence="Low",
                url=url, method=method, parameter=pr,
                evidence=f"Sent controlled callback {callback} — confirm HIT in YOUR callback logs. status={r.status_code}",
                request_summary=req, response_summary=f"status={r.status_code} len={len(r.text or '')}",
                description="A controlled request was sent to your own callback endpoint. Only a hit in your logs proves SSRF.",
                impact="Confirmed SSRF would allow server-side outbound requests.",
                remediation="Validate callback came from target IP; then fix with egress allow-listing.",
                cwe="CWE-918", owasp="A10:2021 - SSRF",
                references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"])
        return self.findings
