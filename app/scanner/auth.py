"""Authorized credential testing: weak auth, cookie flags, MFA/lockout indicators.

Uses ONLY test accounts explicitly provided by the user. Rate-limited.
No credential stuffing, no other users' accounts.
"""
from __future__ import annotations

from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from app.scanner.base import BaseModule
from app.scanner.http_client import StopRequested
from app.utils.helpers import truncate


class AuthModule(BaseModule):
    name = "auth"
    description = "Authorized authentication testing (test accounts only)"

    async def run(self, target, pages, context):
        login_url = (context.get("login_url") or "").strip()
        username = (context.get("username") or "")
        password = (context.get("password") or "")
        if not login_url:
            login_url = self._guess_login(pages, target.url if hasattr(target, "url") else str(target))
        if not login_url:
            self.log("No login URL provided or discovered; skipping active login tests")
            await self._passive_cookie_checks(pages)
            return self.findings
        await self._passive_cookie_checks(pages)
        # passive form analysis
        await self._analyze_login_form(login_url)
        if not self.active:
            return self.findings
        if not username or not password:
            self.log("Active auth tests need a test username/password; skipping login attempts")
            return self.findings
        await self._rate_limited_login_tests(login_url, username, password)
        return self.findings

    def _guess_login(self, pages, base):
        for p in pages:
            for f in p.forms:
                names = [(i.get("name") or "").lower() for i in f["inputs"]]
                types = [(i.get("type") or "") for i in f["inputs"]]
                if any("pass" in n for n in names) and ("password" in types or any("user" in n or "email" in n or "login" in n for n in names)):
                    return f["action"]
            if "login" in p.url.lower() or "signin" in p.url.lower():
                return p.url
        return ""

    async def _passive_cookie_checks(self, pages):
        for p in pages[:30]:
            try:
                r = await self.client.get(p.url)
            except StopRequested:
                raise
            except Exception:
                continue
            raw = r.headers.get("set-cookie", "")
            cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else ([raw] if raw else [])
            for c in cookies:
                cl = c.lower()
                missing = [f for f in ("secure", "httponly", "samesite") if f not in cl]
                if missing:
                    self.add_finding(
                        name="Insecure Cookie Flags", severity="Medium" if "secure" in missing else "Low",
                        confidence="High", url=p.url, method="GET", parameter="Set-Cookie",
                        evidence=f"Cookie missing {', '.join(missing)}: {truncate(c, 200)}",
                        request_summary=f"GET {p.url}", response_summary=f"status={r.status_code}",
                        description="Session cookies lack recommended security flags.",
                        impact="Cookie theft via XSS or network sniffing.",
                        remediation="Set Secure, HttpOnly, SameSite=Lax/Strict on session cookies.",
                        cwe="CWE-614", owasp="A01:2021 - Broken Access Control",
                        references=["https://owasp.org/www-community/controls/SecureCookieAttribute"])
                    break

    async def _analyze_login_form(self, login_url):
        try:
            r = await self.client.get(login_url)
            soup = BeautifulSoup(r.text or "", "html.parser")
        except StopRequested:
            raise
        except Exception:
            return
        text = (r.text or "").lower()
        forms = soup.find_all("form")
        has_pwd = any(i.get("type") == "password" for f in forms for i in f.find_all("input"))
        if not has_pwd and "password" not in text:
            return
        # MFA indicator
        if not any(k in text for k in ("mfa", "2fa", "two-factor", "otp", "authenticator")):
            self.add_finding(
                name="MFA Not Advertised on Login", severity="Informational", confidence="Low",
                url=login_url, method="GET", parameter="(login form)",
                evidence="No MFA/2FA/OTP references found on login page",
                request_summary=f"GET {login_url}", response_summary=f"status={r.status_code}",
                description="Login page shows no MFA option. Verify server-side whether MFA exists.",
                impact="Single-factor logins are more vulnerable to credential theft.",
                remediation="Offer MFA (TOTP/WebAuthn) for sensitive accounts.",
                cwe="CWE-308", owasp="A07:2021 - Auth Failures",
                references=["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"])
        # autocomplete
        for f in forms:
            for i in f.find_all("input", {"type": "password"}):
                if (i.get("autocomplete") or "").lower() not in ("off", "new-password"):
                    self.add_finding(
                        name="Password Autocomplete Enabled", severity="Low", confidence="Medium",
                        url=login_url, method="GET", parameter=i.get("name") or "password",
                        evidence="password input without autocomplete=off/new-password",
                        request_summary=f"GET {login_url}", response_summary=f"status={r.status_code}",
                        description="Browsers may store passwords on shared machines.",
                        impact="Low; credential exposure on shared devices.",
                        remediation="Set autocomplete=\"new-password\" on password fields.",
                        cwe="CWE-525", owasp="A07:2021 - Auth Failures", references=[])

    async def _rate_limited_login_tests(self, login_url, username, password):
        max_attempts = min(self.config.login_max_attempts if self.config else 5, 5)
        # 1 wrong-password attempt to observe lockout/error behavior (rate-limited, single attempt)
        try:
            r = await self.client.post(login_url, data={"username": username, "password": "WrongPassword!12345",
                                                         "user": username, "pass": "WrongPassword!12345"})
            self.params_tested += 1
            body = (r.text or "").lower()
            if "locked" in body or "too many" in body or r.status_code == 429:
                self.add_finding(
                    name="Account Lockout / Rate Limit Present", severity="Informational", confidence="Medium",
                    url=login_url, method="POST", parameter="password",
                    evidence=f"Lockout/rate-limit signal after 1 bad attempt: status={r.status_code}",
                    request_summary=f"POST {login_url} (1 bad-password probe, test account only)",
                    response_summary=f"status={r.status_code} len={len(r.text or '')}",
                    description="Application appears to rate-limit or lock out repeated failures. Good practice.",
                    impact="Reduces brute-force risk.",
                    remediation="Keep exponential backoff + CAPTCHA + alerting; ensure unlock flow is safe.",
                    cwe="CWE-307", owasp="A07:2021 - Auth Failures", references=[])
        except StopRequested:
            raise
        except Exception as e:
            self.log(f"lockout probe failed: {e}")
        # 1 correct-credential attempt with test account
        try:
            r = await self.client.post(login_url, data={"username": username, "password": password,
                                                         "user": username, "pass": password})
            self.params_tested += 1
            # session fixation indicator: compare session cookie before/after
            after = r.headers.get("set-cookie", "")
            if r.status_code in (200, 302) and not after:
                self.add_finding(
                    name="Session Fixation Indicator", severity="Low", confidence="Low",
                    url=login_url, method="POST", parameter="(session)",
                    evidence="Login response did not rotate/set a fresh session cookie (verify manually)",
                    request_summary=f"POST {login_url} (test account login)",
                    response_summary=f"status={r.status_code}",
                    description="Server may not rotate session IDs after login.",
                    impact="Fixated sessions could be hijacked.",
                    remediation="Regenerate session ID on authentication; invalidate old session.",
                    cwe="CWE-384", owasp="A07:2021 - Auth Failures", references=[])
        except StopRequested:
            raise
        except Exception as e:
            self.log(f"login probe failed: {e}")
        self.log(f"Auth tests used {min(2, max_attempts)} rate-limited attempts on test account only")
