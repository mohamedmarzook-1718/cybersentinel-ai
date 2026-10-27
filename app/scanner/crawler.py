"""
Full-Website Safe Crawler Engine for CyberSentinel AI.

Implements:
- Controlled Breadth-First-Search (BFS) same-origin website crawling
- Strict SSRF revalidation on every fetched link
- robots.txt exclusion handling
- Dangerous action link avoidance (logout, delete, drop, cancel)
- Canonical URL normalization and crawler-trap loop prevention
- Discovery of internal links, external dependencies, forms, JavaScript files, and API endpoints
- Profile-based budget enforcement (Passive, Quick, Standard, Comprehensive)
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag
import httpx

from app.scanner.ssrf import validate_target_url, SecurityValidationError


DANGEROUS_PATH_KEYWORDS = {
    "logout", "signout", "sign-out", "log-out",
    "delete", "destroy", "drop", "remove", "cancel",
    "shutdown", "reset", "purge", "unsubscribe"
}

IGNORABLE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".css", ".xml"
}


class WebContentParser(HTMLParser):
    """Safe streaming HTML parser to extract links, forms, scripts, and meta tags."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.scripts: Set[str] = set()
        self.forms: List[Dict] = []
        self.meta_tags: Dict[str, str] = {}
        self.title: str = ""
        self._in_title = False
        self._current_form: Optional[Dict] = None

    def handle_starttag(self, tag: str, attrs: list[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag == "title":
            self._in_title = True

        elif tag == "a":
            href = attr_dict.get("href", "").strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                abs_url = urljoin(self.base_url, href)
                self.links.add(abs_url)

        elif tag == "script":
            src = attr_dict.get("src", "").strip()
            if src:
                self.scripts.add(urljoin(self.base_url, src))

        elif tag == "link":
            rel = attr_dict.get("rel", "").lower()
            href = attr_dict.get("href", "").strip()
            if "icon" in rel or "stylesheet" in rel:
                pass
            elif href:
                self.links.add(urljoin(self.base_url, href))

        elif tag == "meta":
            name = attr_dict.get("name", "").lower() or attr_dict.get("property", "").lower()
            content = attr_dict.get("content", "")
            if name and content:
                self.meta_tags[name] = content

        elif tag == "form":
            action = attr_dict.get("action", "").strip()
            method = attr_dict.get("method", "get").upper()
            form_url = urljoin(self.base_url, action) if action else self.base_url
            self._current_form = {
                "action": form_url,
                "method": method,
                "inputs": [],
            }

        elif tag in ("input", "textarea", "select") and self._current_form is not None:
            name = attr_dict.get("name", "")
            input_type = attr_dict.get("type", "text").lower()
            self._current_form["inputs"].append({
                "name": name,
                "type": input_type,
            })

    def handle_endtag(self, tag: str):
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str):
        if self._in_title and not self.title:
            self.title = data.strip()


class WebsiteCrawler:
    """Robust, scope-enforcing website crawler with rate budgeting and SSRF guards."""

    def __init__(
        self,
        base_url: str,
        profile: str = "standard",
        allowed_domains: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        max_pages: Optional[int] = None,
        timeout: float = 6.0,
    ):
        self.normalized_base, self.target_host, self.target_ip = validate_target_url(base_url)
        self.profile = profile.lower()
        self.allowed_domains = set(d.lower().strip() for d in (allowed_domains or []))
        self.allowed_domains.add(self.target_host.lower())
        self.excluded_paths = [p.lower().strip() for p in (excluded_paths or [])]
        self.timeout = timeout

        # Profile limits
        if max_pages is not None:
            self.max_pages = max_pages
            self.max_depth = 3
        elif self.profile == "passive":
            self.max_pages = 1
            self.max_depth = 0
        elif self.profile == "quick":
            self.max_pages = 10
            self.max_depth = 1
        elif self.profile == "comprehensive":
            self.max_pages = 80
            self.max_depth = 3
        else:  # standard
            self.max_pages = 30
            self.max_depth = 2

        self.robots_disallow: List[str] = []

    def _normalize_link(self, raw_url: str) -> Optional[str]:
        """Normalize URL, strip fragment, verify extension and dangerous keywords."""
        clean_url, _ = urldefrag(raw_url.strip())
        parsed = urlparse(clean_url)
        if parsed.scheme not in ("http", "https"):
            return None

        # Scope enforcement: host must be target or explicitly allowed domain
        host = (parsed.hostname or "").lower()
        if host not in self.allowed_domains:
            return None

        path_lower = parsed.path.lower()

        # Filter out static media/binary files
        if any(path_lower.endswith(ext) for ext in IGNORABLE_EXTENSIONS):
            return None

        # Filter dangerous/destructive action keywords
        for kw in DANGEROUS_PATH_KEYWORDS:
            if re.search(r'(^|/|-|_)' + re.escape(kw) + r'($|/|-|_)', path_lower):
                return None

        # Filter user-excluded paths
        for excl in self.excluded_paths:
            if excl in path_lower:
                return None

        # Filter robots.txt disallow rules
        for dis in self.robots_disallow:
            if dis and path_lower.startswith(dis):
                return None

        return clean_url

    def fetch_robots_txt(self, client: httpx.Client) -> List[str]:
        """Fetch robots.txt safely and extract disallow rules."""
        robots_url = urljoin(self.normalized_base, "/robots.txt")
        disallow_rules = []
        try:
            validate_target_url(robots_url)
            res = client.get(robots_url, timeout=self.timeout)
            if res.status_code == 200 and "text" in res.headers.get("content-type", ""):
                for line in res.text.splitlines():
                    clean_line = line.strip()
                    if clean_line.lower().startswith("disallow:"):
                        path = clean_line.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallow_rules.append(path.lower())
        except Exception:
            pass
        self.robots_disallow = disallow_rules
        return disallow_rules

    def crawl(self) -> Dict:
        """
        Execute breadth-first crawling within configured boundaries.

        Returns:
            Dictionary with crawled pages, discovered URLs, forms, scripts, and API routes.
        """
        crawled_pages: List[Dict] = []
        crawled_urls: Set[str] = set()
        queue: List[Tuple[str, int]] = [(self.normalized_base, 0)]
        discovered_urls: Set[str] = {self.normalized_base}
        discovered_scripts: Set[str] = set()
        discovered_forms: List[Dict] = []
        discovered_apis: Set[str] = set()
        third_party_resources: Set[str] = set()

        headers = {
            "User-Agent": "CyberSentinel-SecurityScanner/2.0 (+https://cybersentinel.ai/bot; passive-audit)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }

        with httpx.Client(
            verify=False,
            timeout=self.timeout,
            headers=headers,
            follow_redirects=True,
            max_redirects=4
        ) as client:
            # 1. Parse robots.txt
            self.fetch_robots_txt(client)

            # 2. BFS Traversal
            while queue and len(crawled_pages) < self.max_pages:
                current_url, depth = queue.pop(0)
                if current_url in crawled_urls:
                    continue

                # Verify SSRF on target URL before every request
                try:
                    validate_target_url(current_url)
                except SecurityValidationError:
                    continue

                crawled_urls.add(current_url)

                try:
                    res = client.get(current_url)
                    status_code = res.status_code
                    content_type = res.headers.get("content-type", "").lower()
                    raw_body = res.text[:200000]  # Cap at 200KB for parsing

                    parser = WebContentParser(current_url)
                    if "html" in content_type:
                        try:
                            parser.feed(raw_body)
                        except Exception:
                            pass

                    # Extract page telemetry
                    crawled_pages.append({
                        "url": current_url,
                        "status_code": status_code,
                        "title": parser.title or urlparse(current_url).path or "/",
                        "content_type": content_type,
                        "body_sample": raw_body[:5000],
                        "headers": dict(res.headers),
                    })

                    # Aggregate scripts, forms, and third party resources
                    for script in parser.scripts:
                        discovered_scripts.add(script)
                        parsed_script = urlparse(script)
                        if parsed_script.hostname and parsed_script.hostname.lower() not in self.allowed_domains:
                            third_party_resources.add(script)

                    for form in parser.forms:
                        discovered_forms.append(form)

                    # Extract inline API endpoint references via regex
                    api_matches = re.findall(r'["\'](/api/[a-zA-Z0-9_\-\./]+)["\']', raw_body)
                    for api_path in api_matches:
                        discovered_apis.add(urljoin(current_url, api_path))

                    # If not at max depth, add newly discovered same-origin links
                    if depth < self.max_depth:
                        for raw_link in parser.links:
                            norm = self._normalize_link(raw_link)
                            if norm:
                                discovered_urls.add(norm)
                                if norm not in crawled_urls and len(discovered_urls) < 150:
                                    queue.append((norm, depth + 1))
                            else:
                                parsed_link = urlparse(raw_link)
                                if parsed_link.hostname and parsed_link.hostname.lower() not in self.allowed_domains:
                                    third_party_resources.add(raw_link)

                except Exception as e:
                    crawled_pages.append({
                        "url": current_url,
                        "status_code": 0,
                        "title": "Error / Timeout",
                        "content_type": "error",
                        "body_sample": str(e),
                        "headers": {},
                    })

        return {
            "crawled_pages": crawled_pages,
            "discovered_urls": sorted(list(discovered_urls)),
            "discovered_scripts": sorted(list(discovered_scripts)),
            "discovered_forms": discovered_forms,
            "discovered_apis": sorted(list(discovered_apis)),
            "third_party_resources": sorted(list(third_party_resources))[:50],
            "robots_disallow": self.robots_disallow,
            "pages_crawled_count": len(crawled_pages),
            "pages_discovered_count": len(discovered_urls),
        }
