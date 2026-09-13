"""Reflected XSS scanner with safe, non-exfiltrating verification payloads."""
from __future__ import annotations

import html as htmlmod
import re

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import set_query_param, truncate

# Benign canary payloads: unique markers, no cookie/credential/token access.
REFLECTED_PAYLOADS = [
    'wgpxss"><svg>',
    'wgpxss\'"><img src=x>',
    '<svg onload>',
    '"><svg>',
    "';wgpxss;//",
    '<script>wgpxss</script>',
]
DOM_SINKS = ["innerHTML", "document.write", "eval(", "location.hash", "outerHTML",
             "insertAdjacentHTML", "document.URL", "location.search"]


class XssModule(BaseModule):
    name = "xss"
    description = "Reflected / stored-indicator / DOM XSS detection (safe payloads)"

    async def run(self, target, pages, context):
        if not self.active:
            # Passive: DOM-sink indicators only
            for p in pages:
                await self._dom_indicators(p.url, p)
            return self.findings
        candidates = self._collect_candidates(pages)
        for url, method, params, form in candidates:
            for param in params[: (self.config.limits.max_params_per_page if self.config else 10)]:
                if self.client.stopped:
                    raise StopRequested("stopped")
                await self._test_param(url, method, param, form)
        return self.findings

    def _collect_candidates(self, pages):
        out = []
        for p in pages:
            if p.get_params:
                out.append((p.url, "GET", list(p.get_params), None))
            for f in p.forms:
                names = [i["name"] for i in f["inputs"] if i["name"]]
                if names:
                    out.append((f["action"], f["method"], names, f))
        # de-dup
        seen, uniq = set(), []
        for item in out:
            key = (item[0], item[1], tuple(item[2]))
            if key not in seen:
                seen.add(key)
                uniq.append(item)
        return uniq[:200]

    async def _dom_indicators(self, url, page):
        try:
            r = await self.client.get(url)
            text = r.text[:20000]
        except StopRequested:
            raise
        except Exception:
            return
        hits = [s for s in DOM_SINKS if s in text]
        if hits:
            self.add_finding(
                name="DOM XSS Sink Indicator", severity="Low", confidence="Low",
                url=url, method="GET", parameter="(inline script analysis)",
                evidence=f"JS sinks referenced: {', '.join(hits[:5])}",
                request_summary=f"GET {url}",
                response_summary=f"status={r.status_code} len={len(text)}",
                description="Page JavaScript references known DOM XSS sinks. Manual review needed.",
                impact="If user input reaches these sinks without encoding, DOM XSS is possible.",
                remediation="Use textContent instead of innerHTML; encode output; apply CSP.",
                cwe="CWE-79", owasp="A03:2021 - Injection",
                references=["https://owasp.org/www-community/attacks/DOM_Based_XSS/"])

    async def _test_param(self, url, method, param, form):
        # baseline
        try:
            if method == "GET":
                base = await self.client.get(url)
                base_text = base.text
            else:
                data = {param: "WebGuardBaseline123"}
                base = await self.client.post(url, data=data)
                base_text = base.text
        except StopRequested:
            raise
        except Exception:
            return
        self.params_tested += 1
        for payload in REFLECTED_PAYLOADS:
            if self.client.stopped:
                raise StopRequested("stopped")
            # only reflect-check the canary token to avoid flagging static content
            token = "wgpxss"
            try:
                if method == "GET":
                    turl = set_query_param(url, param, payload)
                    r = await self.client.get(turl)
                    req = f"GET {truncate(turl, 300)}"
                else:
                    data = {param: payload}
                    r = await self.client.post(url, data=data)
                    req = f"POST {url} param={param}"
                body = r.text
            except StopRequested:
                raise
            except Exception:
                continue
            self.params_tested += 1
            if token not in body:
                continue
            # --- accuracy gate: demand a SECOND confirming payload before flagging ---
            confirm = "wgp2nd\"><svg>"
            try:
                if method == "GET":
                    curl = set_query_param(url, param, confirm)
                    cr = await self.client.get(curl)
                else:
                    cr = await self.client.post(url, data={param: confirm})
                cbody = cr.text or ""
                self.params_tested += 1
            except StopRequested:
                raise
            except Exception:
                continue
            cidx = cbody.find("wgp2nd")
            if cidx < 0:
                continue  # second marker didn't reflect -> not reliably injectable
            cwindow = cbody[max(0, cidx - 120):cidx + 120]
            craw_angle = "<svg" in cwindow or "<img" in cwindow
            # context analysis
            ctx = self._context(body, payload, token)
            unescaped = payload in body or "wgpxss\"><svg>" in body or "<svg" in body[max(0, body.find(token)-60):body.find(token)+60]
            # check if our angle brackets survived unencoded
            idx = body.find(token)
            window = body[max(0, idx - 120):idx + 120]
            raw_angle = "<svg" in window or "<img" in window or "<script>wgpxss" in window
            encoded_only = htmlmod.escape(payload) in body and not raw_angle
            if raw_angle and craw_angle and not encoded_only:
                self.add_finding(
                    name="Reflected XSS", severity="High", confidence="High" if "<svg" in window or "<script" in window else "Medium",
                    url=url, method=method, parameter=param,
                    evidence=f"Canary '{token}' reflected with raw HTML context: {truncate(window, 300)}",
                    request_summary=req,
                    response_summary=f"status={r.status_code} len={len(body)} context={ctx}",
                    description="User input is reflected in the response without proper output encoding.",
                    impact="An attacker could craft a link executing script in a victim's browser (session actions, defacement, phishing).",
                    remediation="Context-aware output encoding, validate input, deploy Content-Security-Policy.",
                    cwe="CWE-79", owasp="A03:2021 - Injection",
                    references=["https://owasp.org/www-community/attacks/xss/"])
                return  # one finding per param is enough
            elif token in body:
                # reflected but encoded -> informational hardening note (only once per param set? keep Low noise minimal)
                pass

    def _context(self, body, payload, token):
        idx = body.find(token)
        if idx < 0:
            return "not-reflected"
        window = body[max(0, idx - 40):idx + 40]
        if "<script" in body[max(0, idx - 500):idx].lower()[-500:]:
            return "inside-script?"
        if re.search(r"<[a-zA-Z][^>]*$", body[:idx][-120:]):
            return "inside-tag-attribute?"
        if "<!--" in body[max(0, idx - 100):idx]:
            return "inside-comment?"
        return "html-body?"
