import asyncio
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass

try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

@dataclass
class BrowserPage:
    url: str
    title: str = ""
    content: str = ""
    screenshot: bytes = b""
    console_messages: list = None
    network_requests: list = None

    def __post_init__(self):
        if self.console_messages is None:
            self.console_messages = []
        if self.network_requests is None:
            self.network_requests = []

class HeadlessBrowser:
    """Playwright-based headless browser for modern web testing."""

    def __init__(self):
        self._playwright = None
        self._browser = None
        self._context = None

    async def start(self, headless=True):
        """Start the browser."""
        if not HAS_PLAYWRIGHT:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install chromium")

        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=headless)
        self._context = await self._browser.new_context(
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )

    async def stop(self):
        """Stop the browser."""
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()

    async def crawl_spa(self, url, max_pages=50, max_depth=3) -> List[dict]:
        """Crawl SPA with JavaScript rendering."""
        visited = set()
        results = []

        async def _crawl(current_url, depth):
            if current_url in visited or depth > max_depth or len(results) >= max_pages:
                return
            visited.add(current_url)

            try:
                page = await self._context.new_page()
                await page.goto(current_url, wait_until="networkidle", timeout=30000)

                title = await page.title()
                content = await page.content()

                results.append({
                    "url": current_url,
                    "title": title,
                    "size": len(content),
                    "depth": depth,
                })

                # Extract links from rendered DOM
                links = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('a[href]'))
                        .map(a => a.href)
                        .filter(h => h.startsWith('http'))
                """)

                await page.close()

                if depth < max_depth:
                    for link in links[:20]:
                        if link not in visited:
                            await _crawl(link, depth + 1)
            except Exception:
                logging.exception("crawl_spa: page crawl failed")

        await _crawl(url, 0)
        return results

    async def detect_dom_xss(self, url, params=None) -> List[dict]:
        """Detect DOM-based XSS via sink/source analysis."""
        findings = []

        sinks = [
            "eval(", "document.write(", "innerHTML", "outerHTML",
            "document.location", "window.location", "setTimeout(",
            "setInterval(", "Function(", "eval(",
        ]

        sources = [
            "location.hash", "location.search", "document.referrer",
            "window.name", "document.cookie", "location.href",
        ]

        try:
            page = await self._context.new_page()

            # Collect console errors
            console_errors = []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

            await page.goto(url, wait_until="networkidle", timeout=30000)

            # Analyze JavaScript for sinks and sources
            js_analysis = await page.evaluate("""
                () => {
                    const scripts = Array.from(document.querySelectorAll('script'));
                    const inlineScripts = scripts.filter(s => !s.src).map(s => s.textContent);
                    return {
                        sinks: %s,
                        sources: %s,
                        inlineScripts: inlineScripts.join('\\n'),
                    };
                }
            """ % (repr(sinks), repr(sources)))

            # Check for DOM XSS patterns
            inline_js = js_analysis.get("inlineScripts", "")
            for source in sources:
                for sink in sinks:
                    if source in inline_js and sink in inline_js:
                        findings.append({
                            "type": "dom_xss_potential",
                            "source": source,
                            "sink": sink,
                            "url": url,
                        })

            # Test with payload in hash
            test_payloads = [
                "#<script>alert(1)</script>",
                "#\"><img src=x onerror=alert(1)>",
                "#javascript:alert(1)",
            ]

            for payload in test_payloads:
                try:
                    await page.goto(f"{url}{payload}", wait_until="networkidle", timeout=10000)
                    dialog_fired = False
                    page.on("dialog", lambda d: setattr(d, '_fired', True) or d.dismiss())
                    await asyncio.sleep(1)
                except Exception:
                    logging.exception("detect_dom_xss: payload navigation failed")

            await page.close()
        except Exception:
            logging.exception("detect_dom_xss: unexpected error")

        return findings

    async def capture_screenshot(self, url) -> bytes:
        """Capture page screenshot."""
        try:
            page = await self._context.new_page()
            await page.goto(url, wait_until="networkidle", timeout=30000)
            screenshot = await page.screenshot(full_page=True)
            await page.close()
            return screenshot
        except Exception:
            logging.exception("capture_screenshot: failed to capture screenshot")
            return b""

    async def extract_js_routes(self, url) -> List[str]:
        """Extract routes from rendered JavaScript."""
        routes = []

        try:
            page = await self._context.new_page()
            await page.goto(url, wait_until="networkidle", timeout=30000)

            # Extract routes from router
            routes = await page.evaluate("""
                () => {
                    const routes = [];
                    // React Router
                    if (window.__NEXT_DATA__) {
                        const data = window.__NEXT_DATA__;
                        if (data.props && data.props.pageProps) {
                            routes.push(...Object.keys(data.props.pageProps));
                        }
                    }
                    // Vue Router
                    if (window.__VUE__) {
                        const app = document.querySelector('#app').__vue_app__;
                        if (app && app.config && app.config.globalProperties && app.config.globalProperties.$router) {
                            app.config.globalProperties.$router.getRoutes().forEach(r => {
                                routes.push(r.path);
                            });
                        }
                    }
                    // Angular Router
                    const ngRoutes = document.querySelectorAll('[routerlink], [ng-reflect-router-link]');
                    ngRoutes.forEach(el => {
                        routes.push(el.getAttribute('routerlink') || el.getAttribute('ng-reflect-router-link'));
                    });
                    // Generic: extract all internal links
                    const links = Array.from(document.querySelectorAll('a[href]'));
                    links.forEach(a => {
                        const href = a.getAttribute('href');
                        if (href && href.startsWith('/') && !href.startsWith('//')) {
                            routes.push(href);
                        }
                    });
                    return [...new Set(routes)];
                }
            """)

            await page.close()
        except Exception:
            logging.exception("extract_js_routes: failed to extract routes")

        return routes

    async def monitor_network(self, url, actions=None) -> List[dict]:
        """Monitor network requests during user actions."""
        requests_log = []

        try:
            page = await self._context.new_page()
            page.on("request", lambda req: requests_log.append({
                "method": req.method,
                "url": req.url,
                "resource_type": req.resource_type,
            }))

            await page.goto(url, wait_until="networkidle", timeout=30000)

            if actions:
                for action in actions:
                    try:
                        await page.evaluate(action)
                        await asyncio.sleep(0.5)
                    except Exception:
                        logging.exception("monitor_network: action execution failed")

            await page.close()
        except Exception:
                    logging.exception("monitor_network: unexpected error")

        return requests_log

    async def test_oauth_flow(self, url, login_url=None, credentials=None) -> dict:
        """Test OAuth2/OIDC flow for vulnerabilities."""
        results = {
            "flows_tested": [],
            "vulnerabilities": [],
            "tokens_found": [],
        }

        try:
            page = await self._context.new_page()
            await page.goto(url, wait_until="networkidle", timeout=30000)

            # Check for OAuth endpoints
            oauth_links = await page.evaluate("""
                () => Array.from(document.querySelectorAll('a[href*="oauth"], a[href*="authorize"], a[href*="auth"]'))
                    .map(a => ({href: a.href, text: a.textContent.trim()}))
            """)

            results["oauth_links"] = oauth_links

            # Check for token leakage in URL
            current_url = page.url
            if "access_token=" in current_url or "id_token=" in current_url:
                results["vulnerabilities"].append({
                    "type": "token_in_url",
                    "detail": "Token found in URL - may be logged in browser history"
                })

            await page.close()
        except Exception:
            logging.exception("test_oauth_flow: unexpected error")

        return results

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.stop()
