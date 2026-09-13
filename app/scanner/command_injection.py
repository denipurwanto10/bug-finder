"""Command Injection detection via non-destructive verification only."""
from __future__ import annotations

import re
import time

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import set_query_param, truncate

# Arithmetic probes prove evaluation: reflection of 'a*b' is ignored,
# only the COMPUTED result counts as evidence. Never destructive.
ARITH_WRAPPERS = [
    (";echo $(({e}))", "echo $(({}))"),
    ("|echo $(({e}))", "echo $(({}))"),
    ("&& echo $(({e}))", "echo $(({}))"),
    ("$(echo $(({e})))", "$(({}))"),
]
ERROR_SIGS = [r"sh:\s", r"/bin/sh", r"command not found", r"syntax error near",
              r"cmd\.exe", r"'.*' is not recognized as"]


class CommandInjectionModule(BaseModule):
    name = "cmdi"
    description = "Command injection indicators (non-destructive probes)"

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

    async def _send(self, url, method, param, value):
        if method == "GET":
            r = await self.client.get(set_query_param(url, param, value))
            req = f"GET {truncate(set_query_param(url, param, value), 300)}"
        else:
            r = await self.client.post(url, data={param: value})
            req = f"POST {url} param={param}"
        self.params_tested += 1
        return r, req

    async def _test(self, url, method, param):
        try:
            base, _ = await self._send(url, method, param, "WebGuardBaseline42")
        except StopRequested:
            raise
        except Exception:
            return
        base_text = base.text or ""
        expr, expected = arithmetic_canary()
        if expected in base_text:
            return  # expected value already present; avoid FP
        for wrapper, _ in ARITH_WRAPPERS:
            if self.client.stopped:
                raise StopRequested("stopped")
            payload = wrapper.format(e=expr)
            try:
                r, req = await self._send(url, method, param, "42" + payload)
            except StopRequested:
                raise
            except Exception:
                continue
            body = r.text or ""
            # Evidence ONLY if computed result appears while raw expression doesn't
            # merely reflect. Reflection of the expression itself is not evidence.
            if expected in body and expected not in base_text:
                # confirm: expression must not be plainly reflected alongside
                if expr.replace("*", "") in body and expr in body:
                    # ambiguous reflection — demand error-signature corroboration
                    pass
                else:
                    self.add_finding(
                        name="Command Injection (Arithmetic Evaluation)", severity="Critical", confidence="High",
                        url=url, method=method, parameter=param,
                        evidence=f"Probe {expr!r} evaluated to {expected} in response (not mere reflection)",
                        request_summary=req, response_summary=f"status={r.status_code} len={len(body)}",
                        description="Server computed an injected arithmetic expression — strong command-evaluation signal.",
                        impact="OS command injection can lead to full server compromise.",
                        remediation="Avoid shell=True/system(); use parameterized APIs; strict allow-list validation.",
                        cwe="CWE-78", owasp="A03:2021 - Injection",
                        references=["https://owasp.org/www-community/attacks/Command_Injection"])
                    return
            for sig in ERROR_SIGS:
                if re.search(sig, body, re.I) and not re.search(sig, base_text, re.I):
                    self.add_finding(
                        name="Command Injection (Error Signature)", severity="High", confidence="Medium",
                        url=url, method=method, parameter=param,
                        evidence=f"Shell error pattern '{sig}' after probe {payload!r} (baseline clean)",
                        request_summary=req, response_summary=f"status={r.status_code} len={len(body)}",
                        description="Shell-like error message appeared after metacharacter probe while baseline lacks it.",
                        impact="Indicates possible command execution path; needs manual verification.",
                        remediation="Never pass user input to a shell; use exec with argument arrays.",
                        cwe="CWE-78", owasp="A03:2021 - Injection",
                        references=["https://owasp.org/www-community/attacks/Command_Injection"])
                    return
        # timing probe (controlled sleep, harmless)
        delay = (self.config.time_based_cmdi_delay if self.config else 2.0)
        try:
            t0 = time.monotonic()
            if method == "GET":
                await self.client.get(set_query_param(url, param, f"42; sleep {delay}"))
            else:
                await self.client.post(url, data={param: f"42; sleep {delay}"})
            elapsed = time.monotonic() - t0
            self.params_tested += 1
            if elapsed >= delay * 0.8:
                t0b = time.monotonic()
                await self._send(url, method, param, "WebGuardBaseline42")
                bel = time.monotonic() - t0b
                if elapsed - bel >= delay * 0.7:
                    self.add_finding(
                        name="Command Injection (Timing Indicator)", severity="High", confidence="Low",
                        url=url, method=method, parameter=param,
                        evidence=f"sleep-probe {elapsed:.2f}s vs baseline {bel:.2f}s",
                        request_summary=f"{method} {url} param={param} (sleep probe, controlled)",
                        response_summary="timing anomaly",
                        description="Response delay matches injected sleep; may indicate command evaluation.",
                        impact="Blind command injection allows attackers to run OS commands.",
                        remediation="Avoid OS calls with user data; sandbox and allow-list inputs.",
                        cwe="CWE-78", owasp="A03:2021 - Injection",
                        references=["https://owasp.org/www-community/attacks/Command_Injection"])
        except StopRequested:
            raise
        except Exception:
            pass
