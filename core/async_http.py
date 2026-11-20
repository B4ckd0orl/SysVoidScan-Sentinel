import asyncio
import time
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

@dataclass
class HTTPResponse:
    """Unified response object."""
    status_code: int = 0
    headers: dict = None
    text: str = ""
    content: bytes = b""
    url: str = ""
    elapsed: float = 0.0
    error: str = ""

    def __post_init__(self):
        if self.headers is None:
            self.headers = {}

class AsyncHTTPEngine:
    """Async HTTP engine with fallback to sync."""

    def __init__(self, config=None):
        self.config = config
        self.max_concurrent = 50
        self.timeout = 30
        self.verify_tls = True
        self._semaphore = None
        self._sync_session = None

    async def get(self, url, headers=None, timeout=None, **kwargs) -> HTTPResponse:
        """Async GET request."""
        if HAS_HTTPX:
            return await self._httpx_get(url, headers, timeout or self.timeout)
        elif HAS_AIOHTTP:
            return await self._aiohttp_get(url, headers, timeout or self.timeout)
        else:
            return self._sync_get(url, headers, timeout or self.timeout)

    async def post(self, url, data=None, json=None, headers=None, timeout=None, **kwargs) -> HTTPResponse:
        """Async POST request."""
        if HAS_HTTPX:
            return await self._httpx_post(url, data, json, headers, timeout or self.timeout)
        elif HAS_AIOHTTP:
            return await self._aiohttp_post(url, data, json, headers, timeout or self.timeout)
        else:
            return self._sync_post(url, data, json, headers, timeout or self.timeout)

    async def request(self, method, url, **kwargs) -> HTTPResponse:
        """Generic async request."""
        timeout = kwargs.pop("timeout", self.timeout)
        if HAS_HTTPX:
            return await self._httpx_request(method, url, timeout=timeout, **kwargs)
        elif HAS_AIOHTTP:
            return await self._aiohttp_request(method, url, timeout=timeout, **kwargs)
        else:
            return self._sync_request(method, url, timeout=timeout, **kwargs)

    async def parallel_requests(self, requests_list: list) -> List[HTTPResponse]:
        """Execute multiple requests in parallel."""
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

        async def _bounded_request(req):
            async with self._semaphore:
                method = req.get("method", "GET")
                url = req.get("url", "")
                return await self.request(method, url, **req)

        tasks = [_bounded_request(req) for req in requests_list]
        return await asyncio.gather(*tasks, return_exceptions=False)

    async def crawl_bfs(self, start_url, max_pages=100, max_depth=3, session=None) -> List[dict]:
        """Async BFS crawler."""
        from urllib.parse import urljoin, urlparse

        visited = set()
        queue = [(start_url, 0)]
        results = []

        while queue and len(results) < max_pages:
            url, depth = queue.pop(0)

            if url in visited or depth > max_depth:
                continue

            visited.add(url)

            try:
                resp = await self.get(url)
                if resp.status_code == 200:
                    results.append({
                        "url": url,
                        "status": resp.status_code,
                        "size": len(resp.content),
                        "depth": depth,
                    })

                    # Extract links
                    if depth < max_depth:
                        links = self._extract_links(resp.text, url)
                        for link in links:
                            if link not in visited and urlparse(link).netloc == urlparse(start_url).netloc:
                                queue.append((link, depth + 1))
            except Exception:
                logging.exception("crawl_bfs: request failed")
                continue

        return results

    def _extract_links(self, html_content, base_url) -> List[str]:
        """Extract links from HTML."""
        import re
        from urllib.parse import urljoin

        links = []
        patterns = [
            r'href=["\']([^"\']+)["\']',
            r'src=["\']([^"\']+)["\']',
            r'action=["\']([^"\']+)["\']',
        ]

        for pattern in patterns:
            for match in re.findall(pattern, html_content):
                if match.startswith(("http://", "https://")):
                    links.append(match)
                elif match.startswith("/"):
                    links.append(urljoin(base_url, match))

        return list(set(links))

    # httpx implementations
    async def _httpx_get(self, url, headers, timeout) -> HTTPResponse:
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=timeout) as client:
                resp = await client.get(url, headers=headers or {})
                return HTTPResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    text=resp.text,
                    content=resp.content,
                    url=str(resp.url),
                    elapsed=resp.elapsed.total_seconds(),
                )
        except Exception as e:
            return HTTPResponse(error=str(e))

    async def _httpx_post(self, url, data, json_data, headers, timeout) -> HTTPResponse:
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=timeout) as client:
                resp = await client.post(url, data=data, json=json_data, headers=headers or {})
                return HTTPResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    text=resp.text,
                    content=resp.content,
                    url=str(resp.url),
                    elapsed=resp.elapsed.total_seconds(),
                )
        except Exception as e:
            return HTTPResponse(error=str(e))

    async def _httpx_request(self, method, url, **kwargs) -> HTTPResponse:
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=kwargs.pop("timeout", self.timeout)) as client:
                resp = await client.request(method, url, **kwargs)
                return HTTPResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    text=resp.text,
                    content=resp.content,
                    url=str(resp.url),
                    elapsed=resp.elapsed.total_seconds(),
                )
        except Exception as e:
            return HTTPResponse(error=str(e))

    # aiohttp implementations
    async def _aiohttp_get(self, url, headers, timeout) -> HTTPResponse:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout), ssl=self.verify_tls) as resp:
                    text = await resp.text()
                    content = await resp.read()
                    return HTTPResponse(
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        text=text,
                        content=content,
                        url=str(resp.url),
                    )
        except Exception as e:
            return HTTPResponse(error=str(e))

    async def _aiohttp_post(self, url, data, json_data, headers, timeout) -> HTTPResponse:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data, json=json_data, headers=headers, timeout=aiohttp.ClientTimeout(total=timeout), ssl=self.verify_tls) as resp:
                    text = await resp.text()
                    content = await resp.read()
                    return HTTPResponse(
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        text=text,
                        content=content,
                        url=str(resp.url),
                    )
        except Exception as e:
            return HTTPResponse(error=str(e))

    async def _aiohttp_request(self, method, url, **kwargs) -> HTTPResponse:
        try:
            timeout = kwargs.pop("timeout", self.timeout)
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=self.verify_tls, **kwargs) as resp:
                    text = await resp.text()
                    content = await resp.read()
                    return HTTPResponse(
                        status_code=resp.status,
                        headers=dict(resp.headers),
                        text=text,
                        content=content,
                        url=str(resp.url),
                    )
        except Exception as e:
            return HTTPResponse(error=str(e))

    # Sync fallback implementations
    def _get_sync_session(self):
        if self._sync_session is None:
            self._sync_session = requests.Session()
            retry = Retry(total=2, backoff_factor=0.5)
            adapter = HTTPAdapter(max_retries=retry, pool_maxsize=self.max_concurrent)
            self._sync_session.mount("http://", adapter)
            self._sync_session.mount("https://", adapter)
        return self._sync_session

    def _sync_get(self, url, headers, timeout) -> HTTPResponse:
        try:
            session = self._get_sync_session()
            resp = session.get(url, headers=headers or {}, timeout=timeout, verify=self.verify_tls, allow_redirects=False)
            return HTTPResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                content=resp.content,
                url=str(resp.url),
                elapsed=resp.elapsed.total_seconds(),
            )
        except Exception as e:
            return HTTPResponse(error=str(e))

    def _sync_post(self, url, data, json_data, headers, timeout) -> HTTPResponse:
        try:
            session = self._get_sync_session()
            resp = session.post(url, data=data, json=json_data, headers=headers or {}, timeout=timeout, verify=self.verify_tls, allow_redirects=False)
            return HTTPResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                content=resp.content,
                url=str(resp.url),
                elapsed=resp.elapsed.total_seconds(),
            )
        except Exception as e:
            return HTTPResponse(error=str(e))

    def _sync_request(self, method, url, **kwargs) -> HTTPResponse:
        try:
            session = self._get_sync_session()
            timeout = kwargs.pop("timeout", self.timeout)
            resp = session.request(method, url, timeout=timeout, verify=self.verify_tls, allow_redirects=False, **kwargs)
            return HTTPResponse(
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                content=resp.content,
                url=str(resp.url),
                elapsed=resp.elapsed.total_seconds(),
            )
        except Exception as e:
            return HTTPResponse(error=str(e))

    def close(self):
        if self._sync_session:
            self._sync_session.close()
