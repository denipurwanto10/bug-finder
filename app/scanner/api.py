"""API security scanner: REST/JSON/GraphQL basic analysis."""
from __future__ import annotations

import json
from urllib.parse import urljoin

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import truncate


class ApiModule(BaseModule):
    name = "api"
    description = "REST/JSON/GraphQL checks: auth, CORS, methods, disclosure"

    async def run(self, target, pages, context):
        base = target.url if hasattr(target, "url") else str(target)
        candidates = list(getattr(context.get("crawler", None), "api_endpoints", []) or [])
        # also probe common API roots
        for suffix in ("/api", "/api/v1", "/graphql", "/api-docs", "/swagger.json",
                       "/openapi.json", "/.well-known/security.txt"):
            candidates.append(urljoin(base + "/", suffix.lstrip("/")))
        seen, uniq = set(), []
        for u in candidates:
            if u not in seen and self.client.sync_check_scope(u):
                seen.add(u); uniq.append(u)
        for url in uniq[:60]:
            if self.client.stopped:
                raise StopRequested("stopped")
            await self._check_endpoint(url)
        # GraphQL introspection (safe, read-only query)
        gql = urljoin(base + "/", "graphql")
        if self.client.sync_check_scope(gql):
            await self._graphql_check(gql)
        return self.findings

    async def _check_endpoint(self, url):
        try:
            r = await self.client.get(url)
        except StopRequested:
            raise
        except Exception:
            return
        body = r.text or ""
        ctype = r.headers.get("content-type", "")
        # skip SPA HTML shells — only assess real JSON/API responses
        if "html" in ctype.lower() or body.lstrip().lower().startswith("<!doctype") or body.lstrip().lower().startswith("<html"):
            return
        # unauthenticated JSON disclosure
        if r.status_code == 200 and ("json" in ctype or body.strip().startswith(("{", "["))):
            keys = []
            try:
                data = json.loads(body[:20000])
                keys = list(data.keys())[:10] if isinstance(data, dict) else [f"item[{i}]" for i in range(min(3, len(data)))]
            except Exception:
                pass
            sensitive = [k for k in keys if any(s in str(k).lower() for s in ("email", "password", "token", "secret", "ssn", "phone", "address"))]
            if sensitive or (keys and "unauth" in url.lower()):
                sev = "High" if sensitive else "Medium"
                self.add_finding(
                    name="API Excessive Data / Unauthenticated Access", severity=sev, confidence="Medium",
                    url=url, method="GET", parameter="(endpoint)",
                    evidence=f"JSON keys: {keys[:8]}; sensitive={sensitive}",
                    request_summary=f"GET {url} (no auth)",
                    response_summary=f"status={r.status_code} len={len(body)}",
                    description="API endpoint returns data without authentication.",
                    impact="Exposure of user/PII data.",
                    remediation="Require auth; minimize fields; paginate; audit logs.",
                    cwe="CWE-200", owasp="API1:2023 - Broken Object Level Authorization",
                    references=["https://owasp.org/API-Security/"])
                return
            if keys:
                self.add_finding(
                    name="API Endpoint Accessible Without Auth", severity="Low", confidence="Medium",
                    url=url, method="GET", parameter="(endpoint)",
                    evidence=f"200 JSON without auth, keys={keys[:8]}",
                    request_summary=f"GET {url}", response_summary=f"status={r.status_code}",
                    description="Verify whether this endpoint should require authentication.",
                    impact="Potential data exposure.",
                    remediation="Enforce authentication/authorization per endpoint.",
                    cwe="CWE-287", owasp="API2:2023 - Broken Authentication", references=[])
                return
        # CORS
        acao = r.headers.get("access-control-allow-origin", "")
        if acao in ("*",) or ("null" in acao.lower()):
            self.add_finding(
                name="Permissive CORS Policy", severity="Medium", confidence="High",
                url=url, method="GET", parameter="Origin",
                evidence=f"Access-Control-Allow-Origin: {acao}",
                request_summary=f"GET {url}", response_summary=f"status={r.status_code}",
                description="Overly permissive CORS allows any site to read responses.",
                impact="Cross-origin data theft when credentials involved.",
                remediation="Echo only trusted origins; never '*' with credentials.",
                cwe="CWE-942", owasp="A01:2021 - Broken Access Control",
                references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"])
        # verbose errors
        bl = body.lower()
        if any(k in bl for k in ("traceback", "stack trace", "exception in", "query failed", "syntax error")):
            self.add_finding(
                name="API Verbose Error Disclosure", severity="Low", confidence="Medium",
                url=url, method="GET", parameter="(endpoint)",
                evidence=truncate(body, 250), request_summary=f"GET {url}",
                response_summary=f"status={r.status_code}",
                description="API leaks stack traces / SQL fragments.",
                impact="Aids attackers in mapping internals.",
                remediation="Generic error messages; log details server-side only.",
                cwe="CWE-209", owasp="A05:2021 - Security Misconfiguration", references=[])
        # HTTP methods
        try:
            o = await self.client.request("OPTIONS", url)
            allow = o.headers.get("allow", "") + " " + o.headers.get("access-control-allow-methods", "")
            risky = [m for m in ("PUT", "DELETE", "PATCH", "TRACE") if m in allow.upper()]
            if risky or o.status_code in (200, 204):
                self.add_finding(
                    name="Unnecessary HTTP Methods Enabled", severity="Low", confidence="Low",
                    url=url, method="OPTIONS", parameter="(methods)",
                    evidence=f"OPTIONS {o.status_code}; Allow-like: {truncate(allow, 150)}",
                    request_summary=f"OPTIONS {url}", response_summary=f"status={o.status_code}",
                    description="Extra HTTP methods may widen attack surface.",
                    impact="Unexpected state changes via PUT/DELETE.",
                    remediation="Disable unneeded methods at server/framework level.",
                    cwe="CWE-749", owasp="A05:2021 - Security Misconfiguration", references=[])
        except StopRequested:
            raise
        except Exception:
            pass

    async def _graphql_check(self, gql):
        q = {"query": "{ __typename }"}
        try:
            r = await self.client.post(gql, json=q)
        except StopRequested:
            raise
        except Exception:
            return
        body = r.text or ""
        if "__typename" in body and r.status_code == 200:
            if "query" in body.lower() and "__schema" in body.lower():
                pass
            # introspection probe (read-only)
            try:
                r2 = await self.client.post(gql, json={"query": "{ __schema { queryType { name } } }"})
                if "__schema" in (r2.text or ""):
                    self.add_finding(
                        name="GraphQL Introspection Enabled", severity="Low", confidence="High",
                        url=gql, method="POST", parameter="query",
                        evidence="Introspection query __schema returned data",
                        request_summary=f"POST {gql} (read-only introspection probe)",
                        response_summary=f"status={r2.status_code}",
                        description="GraphQL schema introspection is enabled in this environment.",
                        impact="Easier API mapping for attackers.",
                        remediation="Disable introspection in production.",
                        cwe="CWE-200", owasp="API9:2023 - Improper Inventory Management",
                        references=["https://owasp.org/API-Security/"])
                    return
            except StopRequested:
                raise
            except Exception:
                pass
            self.add_finding(
                name="GraphQL Endpoint Detected", severity="Informational", confidence="High",
                url=gql, method="POST", parameter="query",
                evidence="GraphQL responded to { __typename }",
                request_summary=f"POST {gql}", response_summary=f"status={r.status_code}",
                description="Review query depth limits, auth, and introspection settings.",
                impact="—", remediation="Depth limiting; cost analysis; auth per field.",
                cwe="CWE-200", owasp="API9:2023", references=[])
