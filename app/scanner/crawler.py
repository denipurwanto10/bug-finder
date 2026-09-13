"""Async web crawler: pages, endpoints, params, forms, JS, APIs, robots/sitemap."""
from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse, parse_qsl

from bs4 import BeautifulSoup

from app.scanner.http_client import StopRequested
from app.utils.models import PageInfo

API_HINT = re.compile(r"/(api|v\d+|graphql|rest|ajax|json)", re.I)
JS_HINT = re.compile(r"\.js($|\?)", re.I)


class Crawler:
    def __init__(self, client, audit=None, depth: int = 2, max_pages: int = 100,
                 max_workers: int = 5, progress_cb=None):
        self.client = client
        self.audit = audit
        self.depth = depth
        self.max_pages = max_pages
        self.max_workers = max_workers
        self.progress_cb = progress_cb
        self.pages: list[PageInfo] = []
        self.js_files: list[str] = []
        self.api_endpoints: list[str] = []
        self.robots_found: list[str] = []
        self.sitemap_found: list[str] = []

    def _msg(self, m: str):
        if self.audit:
            self.audit.info(f"[crawler] {m}")
        if self.progress_cb:
            try:
                self.progress_cb(m)
            except Exception:
                pass

    async def crawl(self, start_url: str) -> list[PageInfo]:
        seen: set[str] = set()
        queue: asyncio.Queue = asyncio.Queue()
        await queue.put((start_url.split("#")[0], 0))
        seen.add(start_url.split("#")[0])
        base_host = urlparse(start_url).hostname or ""

        await self._check_special_files(start_url)

        async def worker():
            while True:
                try:
                    url, depth = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    return
                try:
                    await self._fetch_page(url, depth, queue, seen, base_host)
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.max_workers)]
        try:
            await asyncio.wait_for(queue.join(), timeout=600)
        except asyncio.TimeoutError:
            self._msg("Crawl timed out waiting for queue")
        for w in workers:
            w.cancel()
        return self.pages

    async def _check_special_files(self, start_url: str):
        parts = urlparse(start_url)
        root = f"{parts.scheme}://{parts.netloc}"
        for name in ("robots.txt", "sitemap.xml"):
            url = root + "/" + name
            try:
                r = await self.client.get(url)
                if r.status_code == 200 and len(r.content) < 500_000:
                    text = r.text
                    if name == "robots.txt":
                        self.robots_found.append(url)
                        for line in text.splitlines():
                            line = line.strip()
                            if line.lower().startswith(("disallow:", "allow:", "sitemap:")):
                                path = line.split(":", 1)[1].strip()
                                if path and path not in ("/", "*"):
                                    full = urljoin(root + "/", path)
                                    if self.client.sync_check_scope(full):
                                        self.api_endpoints.append(full)
                        self._msg(f"Found robots.txt ({len(text)} bytes)")
                    else:
                        self.sitemap_found.append(url)
                        for m in re.findall(r"<loc>(.*?)</loc>", text):
                            if self.client.sync_check_scope(m.strip()):
                                self.api_endpoints.append(m.strip())
                        self._msg(f"Found sitemap.xml")
            except StopRequested:
                raise
            except Exception as e:
                self._msg(f"Special file {name} check failed: {e}")

    async def _fetch_page(self, url: str, depth: int, queue, seen: set, base_host: str):
        if len(self.pages) >= self.max_pages:
            return
        try:
            r = await self.client.get(url)
        except StopRequested:
            raise
        except Exception as e:
            self._msg(f"GET failed {url}: {e}")
            return
        ctype = r.headers.get("content-type", "")
        if "html" not in ctype and "text" not in ctype and ctype:
            # still record non-html endpoints
            self.api_endpoints.append(url)
            return
        try:
            text = r.text
        except Exception:
            return
        if len(text) > 2_000_000:
            text = text[:2_000_000]
        soup = BeautifulSoup(text, "html.parser")
        title = (soup.title.string.strip() if soup.title and soup.title.string else "")[:200]

        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or url
            method = (form.get("method") or "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({"name": inp.get("name") or inp.get("id") or "",
                               "type": (inp.get("type") or "text").lower()})
            forms.append({"action": urljoin(url, action), "method": method, "inputs": inputs})

        get_params = [k for k, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]

        js_here, api_here = [], []
        for tag in soup.find_all("script", src=True):
            full = urljoin(url, tag["src"])
            js_here.append(full)
            if full not in self.js_files:
                self.js_files.append(full)
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            if href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            full = urljoin(url, href).split("#")[0]
            if not full.startswith(("http://", "https://")):
                continue
            if not self.client.sync_check_scope(full):
                continue
            if JS_HINT.search(full):
                if full not in self.js_files:
                    self.js_files.append(full)
                continue
            if API_HINT.search(full) or full.endswith((".json", ".xml")):
                if full not in self.api_endpoints:
                    self.api_endpoints.append(full)
                    api_here.append(full)
            if depth < self.depth and full not in seen and len(self.pages) < self.max_pages:
                try:
                    host = urlparse(full).hostname or ""
                except Exception:
                    continue
                # stay on same host or in-scope host
                if host == base_host or self.client.sync_check_scope(full):
                    seen.add(full)
                    await queue.put((full, depth + 1))
        # inline API hints in JS references / fetch calls
        for m in re.findall(r'["\'](/[A-Za-z0-9_\-/\.]{2,120})["\']', text):
            if API_HINT.search(m):
                full = urljoin(url, m)
                if self.client.sync_check_scope(full) and full not in self.api_endpoints:
                    self.api_endpoints.append(full)
        # SPA route discovery: fetch bundled JS and extract routes/endpoints
        await self._mine_js_routes(url, soup, text)

        page = PageInfo(url=url, depth=depth, status=r.status_code, title=title,
                        forms=forms, get_params=get_params,
                        js_files=js_here, api_endpoints=api_here)
        self.pages.append(page)
        self._msg(f"Crawled [{r.status_code}] {url} (forms={len(forms)} params={len(get_params)})")

    async def _mine_js_routes(self, page_url: str, soup, html_text: str):
        """SPA support: download same-origin bundles, extract routes + API paths.

        React/Vue/Angular apps render client-side, so <a> links miss routes.
        We statically scan bundled JS for path strings and common route tables.
        Passive only (plain GET of already-referenced assets).
        """
        from urllib.parse import urlparse as _up
        base_host = _up(page_url).hostname or ""
        bundle_urls = []
        for tag in soup.find_all("script", src=True):
            full = urljoin(page_url, tag["src"])
            try:
                if (_up(full).hostname or "") == base_host and full not in self.js_files:
                    self.js_files.append(full)
                if (_up(full).hostname or "") == base_host:
                    bundle_urls.append(full)
            except Exception:
                continue
        # also inline route tables in HTML (Next.js __NEXT_DATA__, etc.)
        candidates = set(re.findall(r'["\'](/(?:[A-Za-z0-9_\-./]{1,100}))["\']', html_text or ""))
        for m in re.findall(r'"(?:route|path|to)"\s*:\s*"(/[^"]{1,100})"', html_text or ""):
            candidates.add(m)
        for cand in candidates:
            if len(cand) < 2 or "." in cand.rsplit("/", 1)[-1] and not API_HINT.search(cand):
                # skip asset files unless API-like
                if not API_HINT.search(cand):
                    continue
            full = urljoin(page_url, cand)
            if self.client.sync_check_scope(full):
                if API_HINT.search(cand) or cand.endswith((".json",)):
                    if full not in self.api_endpoints:
                        self.api_endpoints.append(full)
                elif full not in getattr(self, "_spa_routes", set()):
                    self._spa_routes = getattr(self, "_spa_routes", set())
                    self._spa_routes.add(full)
        # fetch up to 5 same-origin bundles (bounded, rate-limited via client)
        for burl in bundle_urls[:5]:
            try:
                r = await self.client.get(burl)
                js = (r.text or "")[:500_000]
            except Exception:
                continue
            for pat in (r'["\'](/(?:api|v\d+|graphql|rest|auth|users|posts|data)[A-Za-z0-9_\-/\.]{0,100})["\']',
                        r'fetch\(\s*["\']([^"\']{1,150})["\']',
                        r'axios\.\w+\(\s*["\']([^"\']{1,150})["\']',
                        r'"(?:route|path)"\s*:\s*"(/[^"]{1,100})"'):
                for m in re.findall(pat, js):
                    if m.startswith(("http://", "https://")):
                        full = m
                    else:
                        full = urljoin(page_url, m)
                    if not self.client.sync_check_scope(full):
                        continue
                    if API_HINT.search(m) or m.startswith("/api"):
                        if full not in self.api_endpoints:
                            self.api_endpoints.append(full)
                            self._msg(f"SPA JS reveal: API {m}")
                    elif m.startswith("/") and "." not in m.rsplit("/", 1)[-1]:
                        self._spa_routes = getattr(self, "_spa_routes", set())
                        if full not in self._spa_routes:
                            self._spa_routes.add(full)
                            self._msg(f"SPA JS reveal: route {m}")
