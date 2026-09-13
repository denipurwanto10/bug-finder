"""SQL Injection scanner: error/boolean/time/UNION indicators. Safe payloads only, no dumping."""
from __future__ import annotations

import re
import time

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import response_similarity, set_query_param, stable_response, truncate

DB_ERRORS = [
    (r"SQL syntax.*?MySQL", "MySQL"), (r"Warning.*mysql_", "MySQL"),
    (r"MySQLSyntaxError", "MySQL"), (r"valid MySQL result", "MySQL"),
    (r"ORA-[0-9]{4,5}", "Oracle"), (r"Oracle error", "Oracle"),
    (r"Microsoft SQL Native Client error", "MSSQL"), (r"ODBC SQL Server Driver", "MSSQL"),
    (r"SQLServer JDBC Driver", "MSSQL"), (r"PostgreSQL.*?ERROR", "PostgreSQL"),
    (r"pg_query\(\)", "PostgreSQL"), (r"SQLite.*?error", "SQLite"),
    (r"sqlite3::", "SQLite"), (r"DB2 SQL error", "DB2"),
]
ERROR_PAYLOADS = ["'", '"', "'--", "' OR '1'='1'-- -", "')-- -"]
BOOLEAN_PAIRS = [(" AND 1=1-- -", " AND 1=2-- -"), ("' AND '1'='1'-- -", "' AND '1'='2'-- -")]
UNION_PAYLOADS = ["' UNION SELECT NULL-- -", "' UNION SELECT NULL,NULL-- -", '" UNION SELECT NULL-- -']


class SqliModule(BaseModule):
    name = "sqli"
    description = "Error/boolean/time-based SQLi indicators (no data extraction)"

    async def run(self, target, pages, context):
        if not self.active:
            return self.findings  # SQLi needs active probing
        candidates = []
        for p in pages:
            if p.get_params:
                candidates.append((p.url, "GET", list(p.get_params)))
            for f in p.forms:
                names = [i["name"] for i in f["inputs"] if i["name"]]
                if names:
                    candidates.append((f["action"], f["method"], names))
        seen, uniq = set(), []
        for c in candidates:
            k = (c[0], c[1], tuple(c[2]))
            if k not in seen:
                seen.add(k); uniq.append(c)
        for url, method, params in uniq[:200]:
            for param in params[: (self.config.limits.max_params_per_page if self.config else 10)]:
                if self.client.stopped:
                    raise StopRequested("stopped")
                await self._test_param(url, method, param)
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

    async def _test_param(self, url, method, param):
        try:
            base_resp, base_req = await self._send(url, method, param, "WebGuardBaseline42")
        except StopRequested:
            raise
        except Exception:
            return
        base_text = base_resp.text or ""
        # 1. error-based
        for p in ERROR_PAYLOADS:
            if self.client.stopped:
                raise StopRequested("stopped")
            try:
                r, req = await self._send(url, method, param, p)
            except StopRequested:
                raise
            except Exception:
                continue
            db = self._db_error(r.text or "")
            if db:
                self.add_finding(
                    name=f"SQL Injection (Error-Based, {db})", severity="High", confidence="Medium",
                    url=url, method=method, parameter=param,
                    evidence=f"Database error signature ({db}) after payload {p!r}: {truncate(self._err_snippet(r.text), 300)}",
                    request_summary=req, response_summary=f"status={r.status_code} len={len(r.text or '')}",
                    description="Application returns database error messages for crafted input.",
                    impact="May allow attackers to infer query structure and escalate to data access.",
                    remediation="Use parameterized queries/prepared statements; hide DB errors; least-privilege DB user.",
                    cwe="CWE-89", owasp="A03:2021 - Injection",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"])
                return
        # 2. boolean-based (repeat each side twice; demand stability + divergence)
        for t_payload, f_payload in BOOLEAN_PAIRS:
            if self.client.stopped:
                raise StopRequested("stopped")
            try:
                rt1, _ = await self._send(url, method, param, "42" + t_payload)
                rt2, _ = await self._send(url, method, param, "42" + t_payload)
                rf1, reqf = await self._send(url, method, param, "42" + f_payload)
                rf2, _ = await self._send(url, method, param, "42" + f_payload)
            except StopRequested:
                raise
            except Exception:
                continue
            st1, st2 = stable_response(rt1.text or ""), stable_response(rt2.text or "")
            sf1, sf2 = stable_response(rf1.text or ""), stable_response(rf2.text or "")
            rep_t = response_similarity(st1, st2)
            rep_f = response_similarity(sf1, sf2)
            cross = response_similarity(st1, sf1)
            len_diff = abs(len(st1) - len(sf1))
            base_sim_t = response_similarity(stable_response(base_text), st1)
            # TRUE must be stable AND close to baseline; FALSE stable AND far from TRUE
            if rep_t > 0.97 and rep_f > 0.97 and base_sim_t > 0.95 and cross < 0.90 and len_diff > 50:
                self.add_finding(
                    name="SQL Injection (Boolean-Based Indicator)", severity="High", confidence="High",
                    url=url, method=method, parameter=param,
                    evidence=f"TRUE stable ({rep_t:.2f}, baseline-sim {base_sim_t:.2f}) vs FALSE stable ({rep_f:.2f}); cross-sim={cross:.2f}, len_diff={len_diff}",
                    request_summary=reqf, response_summary=f"status={rf1.status_code} len={len(rf1.text or '')}",
                    description="TRUE condition repeats baseline, FALSE diverges repeatably — injectable parameter.",
                    impact="Blind SQLi can enable systematic data extraction by attackers.",
                    remediation="Parameterized queries; strict input validation; generic error pages.",
                    cwe="CWE-89", owasp="A03:2021 - Injection",
                    references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"])
                return
        # 3. time-based (controlled, single small delay)
        delay = (self.config.time_based_sqli_delay if self.config else 2.0)
        try:
            t0 = time.monotonic()
            if method == "GET":
                await self.client.get(set_query_param(url, param, f"42'; SELECT SLEEP({delay})-- -"))
            else:
                await self.client.post(url, data={param: f"42'; SELECT SLEEP({delay})-- -"})
            elapsed = time.monotonic() - t0
            self.params_tested += 1
            t0b = time.monotonic()
            if method == "GET":
                await self.client.get(set_query_param(url, param, "WebGuardBaseline42"))
            else:
                await self.client.post(url, data={param: "WebGuardBaseline42"})
            baseline_elapsed = time.monotonic() - t0b
            self.params_tested += 1
            if elapsed >= delay * 0.8 and elapsed - baseline_elapsed >= delay * 0.7:
                self.add_finding(
                    name="SQL Injection (Time-Based Indicator)", severity="High", confidence="Low",
                    url=url, method=method, parameter=param,
                    evidence=f"Injected response {elapsed:.2f}s vs baseline {baseline_elapsed:.2f}s",
                    request_summary=f"{method} {url} param={param} (SLEEP probe, controlled {delay}s)",
                    response_summary=f"timing anomaly detected",
                    description="Response timing suggests the database may be evaluating injected timing functions.",
                    impact="Time-based blind SQLi enables data exfiltration one bit at a time.",
                    remediation="Parameterized queries; WAF rate limiting is not a fix — fix the query.",
                    cwe="CWE-89", owasp="A03:2021 - Injection",
                    references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection"])
                return
        except StopRequested:
            raise
        except Exception:
            pass
        # 4. UNION indicators
        for p in UNION_PAYLOADS:
            if self.client.stopped:
                raise StopRequested("stopped")
            try:
                r, req = await self._send(url, method, param, "42" + p)
            except StopRequested:
                raise
            except Exception:
                continue
            sim = response_similarity(base_text, r.text or "")
            if 0.5 < sim < 0.97 and abs(len(r.text or "") - len(base_text)) > 100:
                self.add_finding(
                    name="SQL Injection (UNION Indicator)", severity="Medium", confidence="Low",
                    url=url, method=method, parameter=param,
                    evidence=f"UNION probe changed response (similarity={sim:.2f}, payload={p!r})",
                    request_summary=req, response_summary=f"status={r.status_code} len={len(r.text or '')}",
                    description="UNION SELECT probe altered the response, worth manual verification.",
                    impact="UNION-based SQLi can return database contents in the page.",
                    remediation="Parameterized queries; minimize DB error output.",
                    cwe="CWE-89", owasp="A03:2021 - Injection",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"])
                return

    def _db_error(self, text):
        for rx, label in DB_ERRORS:
            if re.search(rx, text or "", re.I):
                return label
        return ""

    def _err_snippet(self, text):
        for rx, _ in DB_ERRORS:
            m = re.search(rx, text or "", re.I)
            if m:
                s = max(0, m.start() - 60)
                return (text or "")[s:m.end() + 60]
        return (text or "")[:200]
