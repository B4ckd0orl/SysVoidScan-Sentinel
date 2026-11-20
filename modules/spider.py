import re
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse

from core.config import Config
from core.utils import (
    print_info, print_good, print_warning, print_error,
    print_phase, get_session, normalize_url,
)
from lib.payloads import Payloads
from lib.wordlists import Wordlists
import logging


class SpiderModule:
    def __init__(self, scanner):
        self.scanner = scanner
        self.config = scanner.config
        self.payloads = Payloads()
        self.wordlists = Wordlists()

    def spider_website(self, target, session, max_pages=100, max_depth=3, use_robots=True):
        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        base_domain = parsed.netloc

        visited = set()
        queue = [(target, 0)]
        forms = []
        links = []
        scripts = []
        emails = set()
        phones = set()
        comments = []
        hidden_fields = []

        robots_paths = ["/robots.txt", "/sitemap.xml"]

        if use_robots:
            for robots_path in robots_paths:
                robots_url = f"{base_url}{robots_path}"
                try:
                    resp = session.get(robots_url, timeout=self.config.timeout,
                                       verify=self.config.verify_tls)
                    if resp.status_code == 200:
                        body = resp.text or ""
                        disallowed = re.findall(r'Disallow:\s*(\S+)', body)
                        sitemap_urls = re.findall(r'Sitemap:\s*(\S+)', body)

                        for path in disallowed[:50]:
                            clean_path = path.split("#")[0].strip()
                            if clean_path and clean_path.startswith("/"):
                                found_url = f"{base_url}{clean_path}"
                                if found_url not in visited:
                                    queue.append((found_url, 0))

                        for sitemap_url in sitemap_urls[:10]:
                            if sitemap_url not in visited:
                                try:
                                    sm_resp = session.get(sitemap_url, timeout=10,
                                                          verify=self.config.verify_tls)
                                    if sm_resp.status_code == 200:
                                        sm_urls = re.findall(
                                            r'<loc>([^<]+)</loc>',
                                            sm_resp.text or "",
                                        )
                                        for sm_url in sm_urls[:100]:
                                            if base_domain in sm_url and sm_url not in visited:
                                                queue.append((sm_url, 0))
                                except Exception:
                                    logging.exception("spider.py: exception", exc_info=True)
                                    continue
                        print_info(f"Loaded robots.txt: {len(disallowed)} disallowed paths, "
                                   f"{len(sitemap_urls)} sitemaps")
                except Exception:
                    logging.exception("spider.py: exception", exc_info=True)
                    continue
        link_pattern = re.compile(
            r'href=["\']([^"\'#]+)["\']',
            re.IGNORECASE,
        )
        form_pattern = re.compile(
            r'<form[^>]*>(.*?)</form>',
            re.IGNORECASE | re.DOTALL,
        )
        script_pattern = re.compile(
            r'<script[^>]*src=["\']([^"\']+)["\']',
            re.IGNORECASE,
        )
        email_pattern = re.compile(
            r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+',
        )
        phone_pattern = re.compile(
            r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}',
        )
        comment_pattern = re.compile(
            r'<!--(.*?)-->',
            re.DOTALL,
        )
        hidden_input_pattern = re.compile(
            r'<input[^>]*type=["\']hidden["\'][^>]*>',
            re.IGNORECASE,
        )

        print_info(f"Starting web spider from {target} (max_pages={max_pages}, max_depth={max_depth})")

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)

            normalized = self._normalize_spider_url(url)
            if normalized in visited:
                continue
            if depth > max_depth:
                continue

            url_parsed = urlparse(url)
            if url_parsed.netloc and url_parsed.netloc != base_domain:
                continue

            visited.add(normalized)

            try:
                resp = session.get(
                    url,
                    timeout=self.config.timeout,
                    verify=self.config.verify_tls,
                    allow_redirects=True,
                )

                content_type = resp.headers.get("Content-Type", "")
                if "text/html" not in content_type and "javascript" not in content_type:
                    continue

                body = resp.text or ""
                final_url = resp.url

                link_matches = link_pattern.findall(body)
                for link in link_matches:
                    absolute = urljoin(final_url, link)
                    link_parsed = urlparse(absolute)

                    if link_parsed.netloc and link_parsed.netloc != base_domain:
                        continue

                    clean_url = self._normalize_spider_url(absolute)
                    if clean_url not in visited:
                        queue.append((absolute, depth + 1))
                        links.append({
                            "source": url,
                            "target": absolute,
                            "depth": depth,
                        })

                form_matches = form_pattern.findall(body)
                for form_html in form_matches:
                    action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
                    method_match = re.search(r'method=["\'](\w+)["\']', form_html, re.IGNORECASE)

                    action = action_match.group(1) if action_match else ""
                    method = method_match.group(1).upper() if method_match else "GET"

                    inputs = re.findall(
                        r'<input[^>]*name=["\']([^"\']+)["\']',
                        form_html, re.IGNORECASE,
                    )

                    form_url = urljoin(final_url, action) if action else final_url

                    form_entry = {
                        "url": url,
                        "action": form_url,
                        "method": method,
                        "inputs": inputs,
                    }
                    forms.append(form_entry)

                    for hidden_match in hidden_input_pattern.findall(form_html):
                        name_match = re.search(r'name=["\']([^"\']+)["\']', hidden_match, re.IGNORECASE)
                        value_match = re.search(r'value=["\']([^"\']*)["\']', hidden_match, re.IGNORECASE)
                        if name_match:
                            hidden_fields.append({
                                "form_url": form_url,
                                "field": name_match.group(1),
                                "value": value_match.group(1) if value_match else "",
                            })

                script_matches = script_pattern.findall(body)
                for script_src in script_matches:
                    script_url = urljoin(final_url, script_src)
                    scripts.append({
                        "source": url,
                        "url": script_url,
                    })

                email_matches = email_pattern.findall(body)
                for email in email_matches:
                    if not email.endswith(('.png', '.jpg', '.gif', '.css', '.js')):
                        emails.add(email)

                phone_matches = phone_pattern.findall(body)
                for phone in phone_matches:
                    cleaned = re.sub(r'[^\d+]', '', phone)
                    if len(cleaned) >= 7:
                        phones.add(phone.strip())

                comment_matches = comment_pattern.findall(body)
                for comment in comment_matches:
                    comment_stripped = comment.strip()
                    if len(comment_stripped) > 5 and len(comment_stripped) < 500:
                        sensitive_kw = [
                            'password', 'secret', 'key', 'token', 'api',
                            'todo', 'fixme', 'hack', 'debug', 'admin',
                        ]
                        if any(kw in comment_stripped.lower() for kw in sensitive_kw):
                            comments.append({
                                "url": url,
                                "comment": comment_stripped[:200],
                            })

                if len(visited) % 10 == 0:
                    print_info(f"  Crawled {len(visited)} pages, queue: {len(queue)}")

                time.sleep(self.config.request_delay)

            except Exception:
                logging.exception("spider.py: exception", exc_info=True)
                continue
        self.config.scan_data["crawl"]["urls"] = list(visited)
        self.config.scan_data["crawl"]["forms"] = forms
        self.config.scan_data["crawl"]["links"] = links
        self.config.scan_data["crawl"]["scripts"] = scripts
        self.config.scan_data["crawl"]["emails"] = list(emails)
        self.config.scan_data["crawl"]["phones"] = list(phones)
        self.config.scan_data["crawl"]["comments"] = comments
        self.config.scan_data["crawl"]["hidden_fields"] = hidden_fields

        result = {
            "pages_crawled": len(visited),
            "forms_found": len(forms),
            "links_found": len(links),
            "scripts_found": len(scripts),
            "emails_found": len(emails),
            "phones_found": len(phones),
            "sensitive_comments": len(comments),
            "hidden_fields": len(hidden_fields),
        }

        print_good(
            f"Spider complete: {result['pages_crawled']} pages, "
            f"{result['forms_found']} forms, "
            f"{result['links_found']} links, "
            f"{result['scripts_found']} scripts, "
            f"{result['emails_found']} emails, "
            f"{result['sensitive_comments']} sensitive comments"
        )

        return result

    def _normalize_spider_url(self, url):
        try:
            parsed = urlparse(url)
            path = parsed.path.rstrip("/") if parsed.path != "/" else "/"
            normalized = f"{parsed.scheme}://{parsed.netloc}{path}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            return normalized
        except Exception:
            logging.exception("spider.py: operation failed")
            return url

    def run(self, target, session=None):
        print_phase("Web Spider")
        self.config.target_url = normalize_url(target)

        if session is None:
            session = get_session()
        if session is None:
            print_error("Cannot proceed without a valid HTTP session.")
            return

        result = self.spider_website(target, session)

        for email in self.config.scan_data["crawl"]["emails"]:
            finding = {
                "type": "info_disclosure",
                "severity": "info",
                "url": target,
                "evidence": f"Email found: {email}",
            }
            if finding not in self.config.findings:
                self.config.findings.append(finding)

        for comment in self.config.scan_data["crawl"]["comments"]:
            finding = {
                "type": "info_disclosure",
                "severity": "low",
                "url": comment["url"],
                "evidence": f"Sensitive comment: {comment['comment'][:100]}",
            }
            if finding not in self.config.findings:
                self.config.findings.append(finding)

        return result
