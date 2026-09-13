"""Rate-limited async HTTP client with scope enforcement and STOP support."""
from __future__ import annotations

import asyncio
import time
from typing import Optional
from urllib.parse import urlparse

import httpx

from app.utils.scope import ScopeGuard, ScopeViolation


class StopRequested(Exception):
    pass


class HttpClient:
    def __init__(self, scope: list[str], user_agent: str = "WebGuardPro/1.0",
                 rps: float = 5.0, timeout: float = 15.0, max_requests: int = 500,
                 audit=None):
        self.guard = ScopeGuard(scope)
        self.rps = max(0.5, rps)
        self.timeout = timeout
        self.max_requests = max_requests
        self.audit = audit
        self.requests_sent = 0
        self._stop = False
        self._lock = asyncio.Lock()
        self._last_ts = 0.0
        self._client: Optional[httpx.AsyncClient] = None
        self.headers = {"User-Agent": user_agent, "Accept": "text/html,application/json,*/*"}

    def stop(self):
        self._stop = True

    @property
    def stopped(self) -> bool:
        return self._stop

    async def __aenter__(self):
        self._client = httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True, max_redirects=5,
            headers=self.headers, verify=False)
        return self

    async def __aexit__(self, *a):
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _throttle(self):
        async with self._lock:
            now = time.monotonic()
            gap = 1.0 / self.rps
            wait = self._last_ts + gap - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_ts = time.monotonic()

    async def request(self, method: str, url: str, **kwargs):
        if self._stop:
            raise StopRequested("Scan stopped by user")
        self.guard.check(url)
        if self.requests_sent >= self.max_requests:
            raise StopRequested(f"Maximum requests reached ({self.max_requests})")
        await self._throttle()
        if self._stop:
            raise StopRequested("Scan stopped by user")
        kwargs.setdefault("timeout", self.timeout)
        t0 = time.monotonic()
        try:
            resp = await self._client.request(method, url, **kwargs)
        except httpx.TimeoutException as e:
            raise e
        elapsed = time.monotonic() - t0
        self.requests_sent += 1
        resp.elapsed_time = elapsed  # type: ignore
        return resp

    async def get(self, url: str, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self.request("POST", url, **kwargs)

    def sync_check_scope(self, url: str) -> bool:
        return self.guard.allowed(url)
