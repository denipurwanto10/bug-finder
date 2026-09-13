"""JWT security analyzer: header/payload inspection only, no token theft."""
from __future__ import annotations

import base64
import json
import re
import time

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import truncate


def b64url_decode(s: str) -> dict:
    s += "=" * (-len(s) % 4)
    return json.loads(base64.urlsafe_b64decode(s.encode()).decode("utf-8", "replace"))


class JwtModule(BaseModule):
    name = "jwt"
    description = "JWT algorithm/expiry/issuer/config analysis"

    async def run(self, target, pages, context):
        tokens = set()
        for p in pages[:40]:
            try:
                r = await self.client.get(p.url)
            except StopRequested:
                raise
            except Exception:
                continue
            text = r.text or ""
            for m in re.findall(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", text):
                tokens.add((p.url, m))
            for c in (r.headers.get("set-cookie", ""), r.headers.get("authorization", "")):
                for m in re.findall(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", c or ""):
                    tokens.add((p.url, m))
        extra = (context.get("jwt") or "").strip()
        if extra:
            tokens.add(("user-provided", extra))
        for url, tok in list(tokens)[:10]:
            self._analyze(url, tok)
        return self.findings

    def _analyze(self, url, tok):
        try:
            header_b64, payload_b64, _sig = tok.split(".")
            header = b64url_decode(header_b64)
            payload = b64url_decode(payload_b64)
        except Exception:
            return
        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            self.add_finding(
                name="JWT Uses 'none' Algorithm", severity="Critical", confidence="High",
                url=url, method="GET", parameter="(Authorization/JWT)",
                evidence=f"header={truncate(json.dumps(header), 200)}",
                request_summary=f"GET {url}", response_summary="JWT header analysis",
                description="Tokens accept the 'none' algorithm: signatures can be stripped.",
                impact="Full authentication bypass.",
                remediation="Reject alg=none; enforce allow-listed algorithms (RS256/ES256).",
                cwe="CWE-327", owasp="API2:2023 - Broken Authentication",
                references=["https://owasp.org/www-community/vulnerabilities/Improper_JWT_Signature_Verification"])
        if alg == "hs256":
            self.add_finding(
                name="JWT Uses Symmetric HS256 (Review Key Strength)", severity="Low", confidence="Low",
                url=url, method="GET", parameter="(JWT)",
                evidence=f"alg={header.get('alg')}",
                request_summary=f"GET {url}", response_summary="JWT header analysis",
                description="HS256 is fine with a strong secret, risky with weak/shared secrets.",
                impact="Weak secrets allow token forgery.",
                remediation="Use 256-bit+ random secret or asymmetric RS256; rotate keys.",
                cwe="CWE-327", owasp="API2:2023", references=[])
        if "exp" not in payload:
            self.add_finding(
                name="JWT Missing Expiration (exp)", severity="Medium", confidence="High",
                url=url, method="GET", parameter="(JWT)",
                evidence=f"payload keys={list(payload.keys())[:10]}",
                request_summary=f"GET {url}", response_summary="JWT payload analysis",
                description="Token never expires.",
                impact="Stolen tokens remain valid indefinitely.",
                remediation="Set short exp; add iat/nbf; implement revocation/rotation.",
                cwe="CWE-613", owasp="API2:2023", references=[])
        else:
            try:
                ttl = float(payload["exp"]) - time.time()
                if ttl > 86400 * 7:
                    self.add_finding(
                        name="JWT Excessive Lifetime", severity="Low", confidence="Medium",
                        url=url, method="GET", parameter="exp",
                        evidence=f"expires in ~{ttl/86400:.1f} days",
                        request_summary=f"GET {url}", response_summary="JWT payload analysis",
                        description="Token lifetime is very long.",
                        impact="Larger window after token theft.",
                        remediation="Short expirations + refresh-token rotation.",
                        cwe="CWE-613", owasp="API2:2023", references=[])
            except Exception:
                pass
        if "iss" not in payload or "aud" not in payload:
            self.add_finding(
                name="JWT Missing iss/aud Claims", severity="Low", confidence="Medium",
                url=url, method="GET", parameter="(JWT claims)",
                evidence=f"keys={list(payload.keys())[:10]}",
                request_summary=f"GET {url}", response_summary="JWT payload analysis",
                description="No issuer/audience binding; tokens may be replayed across services.",
                impact="Cross-service token replay.",
                remediation="Validate iss and aud on every request.",
                cwe="CWE-287", owasp="API2:2023", references=[])
        sensitive = [k for k in payload.keys() if any(s in str(k).lower() for s in ("password", "ssn", "secret", "card"))]
        if sensitive:
            self.add_finding(
                name="JWT Contains Sensitive Claims", severity="Medium", confidence="High",
                url=url, method="GET", parameter="(JWT payload)",
                evidence=f"sensitive claims: {sensitive} (values masked)",
                request_summary=f"GET {url}", response_summary="JWT payload analysis (values not stored)",
                description="JWT payload is only base64 — readable by anyone holding the token.",
                impact="PII/secret disclosure.",
                remediation="Keep only user id/roles in JWT; fetch the rest server-side.",
                cwe="CWE-200", owasp="API2:2023", references=[])
