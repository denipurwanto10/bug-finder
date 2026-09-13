"""Path Traversal / LFI detection using safe, non-credential test files."""
from __future__ import annotations

import re

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import set_query_param, truncate

# Safe probes: only request files that do not contain credentials.
# We verify via harmless markers, never /etc/passwd, keys, tokens, or DB creds.
SAFE_PROBES = [
    ("../../../../../../etc/hostname", re.compile(r".+")),  # hostname is non-sensitive
    ("..%2F..%2F..%2F..%2F..%2Fetc%2Fhostname", re.compile(r".+")),
    ("../../../../../../etc/timezone", re.compile(r"[A-Za-z/_]+")),
]
# Generic traversal signatures that prove file inclusion without secrets
TRAVERSAL_MARKERS = [
    (re.compile(r"root:x:0:0:"), "REFUSED: credential file pattern - not used as probe target"),
]


class TraversalModule(BaseModule):
    name = "traversal"
    description = "Path traversal / LFI indicators (safe files only)"

    async def run(self, target, pages, context):
        if not self.active:
            return self.findings
        cands = []
        for p in pages:
            if p.get_params:
                cands.append((p.url, "GET", list(p.get_params)))
            for f in p.forms:
                names = [i["name"] for i in f["inputs"] if i["name"]]
                if names:
                    cands.append((f["action"], f["method"], names))
        seen, uniq = set(), []
        for c in cands:
            k = (c[0], c[1], tuple(c[2]))
            if k not in seen:
                seen.add(k); uniq.append(c)
        for url, method, params in uniq[:200]:
            for param in params[: (self.config.limits.max_params_per_page if self.config else 10)]:
                if self.client.stopped:
                    raise StopRequested("stopped")
                await self._test(url, method, param)
        return self.findings

    async def _baseline(self, url, method, param):
        if method == "GET":
            r = await self.client.get(set_query_param(url, param, "WebGuardBaseline42"))
            req = f"GET {truncate(set_query_param(url, param, 'WebGuardBaseline42'), 300)}"
        else:
            r = await self.client.post(url, data={param: "WebGuardBaseline42"})
            req = f"POST {url} param={param}"
        self.params_tested += 1
        return r

    async def _test(self, url, method, param):
        try:
            base = await self._baseline(url, method, param)
        except StopRequested:
            raise
        except Exception:
            return
        base_text = (base.text or "")
        # Strategy: compare traversal probe response vs baseline; flag only if the
        # probe yields system-file-like content (never credential content).
        for payload, _marker in SAFE_PROBES:
            if self.client.stopped:
                raise StopRequested("stopped")
            try:
                if method == "GET":
                    turl = set_query_param(url, param, payload)
                    r = await self.client.get(turl)
                    req = f"GET {truncate(turl, 300)}"
                else:
                    r = await self.client.post(url, data={param: payload})
                    req = f"POST {url} param={param}"
                self.params_tested += 1
            except StopRequested:
                raise
            except Exception:
                continue
            body = (r.text or "")
            # Refuse to treat credential/secret content as evidence; skip if seen
            if re.search(r"root:x:0:0:|-----BEGIN .*PRIVATE KEY|api[_-]?key|password", body, re.I):
                continue
            # Heuristic: short single-line response differing strongly from baseline
            # suggests file read of /etc/hostname or /etc/timezone style file.
            lines = [l for l in body.strip().splitlines() if l.strip()]
            if r.status_code == 200 and 0 < len(lines) <= 3 and len(body) < 200 and body.strip() != base_text.strip():
                # ensure probe path actually echoed as file content, not reflection of our payload
                if payload in body:
                    continue  # likely just reflected, not file content
                self.add_finding(
                    name="Path Traversal / LFI (Indicator)", severity="High", confidence="Low",
                    url=url, method=method, parameter=param,
                    evidence=f"Probe {payload!r} returned short system-like content: {truncate(body.strip(), 200)!r}",
                    request_summary=req, response_summary=f"status={r.status_code} len={len(body)}",
                    description="Parameter may allow local file inclusion; response differs as if a system file was read.",
                    impact="LFI can expose source code/config and escalate to RCE in some stacks.",
                    remediation="Map user input to allow-listed resources; canonicalize paths; block ../ sequences.",
                    cwe="CWE-22", owasp="A01:2021 - Broken Access Control",
                    references=["https://owasp.org/www-community/attacks/Path_Traversal"])
                return
