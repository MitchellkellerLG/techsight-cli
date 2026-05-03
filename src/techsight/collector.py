"""Evidence collection — fetches HTTP, DNS, and TLS data for a domain."""

from __future__ import annotations

import re
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import httpx

from techsight.detector import Evidence


MAX_BODY_BYTES = 2 * 1024 * 1024  # 2MB
HTTP_TIMEOUT = 15  # seconds
DNS_TIMEOUT = 5


def _parse_script_sources(html: str) -> list[str]:
    """Extract all script src attributes from HTML."""
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)


def _parse_meta_tags(html: str) -> dict[str, str]:
    """Extract meta tag name/property -> content mappings."""
    tags: dict[str, str] = {}
    for match in re.finditer(
        r'<meta[^>]+(?:name|property)=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']',
        html,
        re.IGNORECASE,
    ):
        tags[match.group(1).lower()] = match.group(2)
    # Also match reverse order (content before name)
    for match in re.finditer(
        r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:name|property)=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    ):
        tags[match.group(2).lower()] = match.group(1)
    return tags


def _parse_cookies(response: httpx.Response) -> dict[str, str]:
    """Extract cookies from response headers."""
    cookies: dict[str, str] = {}
    for cookie in response.cookies.jar:
        cookies[cookie.name] = cookie.value or ""
    # Also parse raw Set-Cookie headers for patterns
    for val in response.headers.get_list("set-cookie"):
        parts = val.split(";")[0].split("=", 1)
        if len(parts) == 2:
            cookies[parts[0].strip()] = parts[1].strip()
        elif len(parts) == 1:
            cookies[parts[0].strip()] = ""
    return cookies


def _parse_internal_links(html: str, domain: str) -> list[str]:
    """Extract unique internal paths from homepage HTML. Returns paths like /demo."""
    seen: set[str] = set()
    paths: list[str] = []
    for match in re.finditer(r'<a[^>]+href=["\']([^"\']+)["\']', html, re.IGNORECASE):
        href = match.group(1).strip()
        if href.startswith("/") and not href.startswith("//"):
            path = href.split("?")[0].split("#")[0].rstrip("/")
            if path and path not in seen:
                seen.add(path)
                paths.append(path)
        elif href.startswith(f"https://{domain}") or href.startswith(f"http://{domain}"):
            from urllib.parse import urlparse
            parsed = urlparse(href)
            path = parsed.path.rstrip("/")
            if path and path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def _fetch_deep_pages(domain: str, homepage_html: str, max_pages: int = 10) -> tuple[str, list[str]]:
    """Fetch up to max_pages internal subpages discovered from homepage links.

    Returns (extra_html, extra_script_sources) merged from all subpages.
    Gracefully skips pages that error or timeout.
    """
    paths = _parse_internal_links(homepage_html, domain)[:max_pages]
    if not paths:
        return "", []

    def _fetch_one(path: str) -> tuple[str, list[str]]:
        try:
            with httpx.Client(
                timeout=HTTP_TIMEOUT,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; TechSight/0.1)"},
            ) as client:
                resp = client.get(f"https://{domain}{path}")
                if resp.status_code < 400:
                    page_html = resp.text[:MAX_BODY_BYTES]
                    return page_html, _parse_script_sources(page_html)
        except Exception:
            pass
        return "", []

    extra_html_parts: list[str] = []
    extra_scripts: list[str] = []

    with ThreadPoolExecutor(max_workers=min(len(paths), 10)) as pool:
        for page_html, page_scripts in pool.map(_fetch_one, paths):
            if page_html:
                extra_html_parts.append(page_html)
            extra_scripts.extend(page_scripts)

    return "\n".join(extra_html_parts), extra_scripts


def _fetch_http(domain: str) -> Evidence:
    """Fetch HTTP response and extract evidence."""
    evidence = Evidence(domain=domain)

    try:
        with httpx.Client(
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
            verify=False,
            limits=httpx.Limits(max_connections=10),
            headers={"User-Agent": "Mozilla/5.0 (compatible; TechSight/0.1)"},
        ) as client:
            url = f"https://{domain}"
            response = client.get(url)

            evidence.url = str(response.url)
            evidence.status_code = response.status_code
            evidence.headers = {k.lower(): v for k, v in response.headers.items()}
            evidence.cookies = _parse_cookies(response)

            if response.status_code < 400:
                html = response.text[:MAX_BODY_BYTES]
                evidence.html = html
                evidence.script_sources = _parse_script_sources(html)
                evidence.meta_tags = _parse_meta_tags(html)

    except httpx.HTTPError as e:
        evidence.error = str(e)
    except Exception as e:
        evidence.error = str(e)

    return evidence


def _fetch_dns_txt(domain: str) -> list[str]:
    """Fetch DNS TXT records for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = resolver.resolve(domain, "TXT")
        records = []
        for rdata in answers:
            for txt in rdata.strings:
                records.append(txt.decode("utf-8", errors="replace"))
        return records
    except Exception:
        return []


def _fetch_robots_txt(domain: str) -> str:
    """Fetch and return robots.txt content."""
    try:
        with httpx.Client(
            timeout=8,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; TechSight/0.1)"},
        ) as client:
            resp = client.get(f"https://{domain}/robots.txt")
            if resp.status_code == 200 and "text" in resp.headers.get("content-type", "text"):
                return resp.text[:50_000]
    except Exception:
        pass
    return ""


# Subdomain prefixes worth resolving CNAME for — these commonly indicate SaaS tools
_CNAME_RESOLVE_PREFIXES = frozenset([
    "help", "support", "go", "pages", "info", "blog", "chat", "app",
    "docs", "status", "community", "kb", "knowledge", "portal", "login",
    "mail", "email", "crm", "meetings", "book", "calendar",
])


def _resolve_cnames(subdomains: list[str], max_lookups: int = 25) -> dict[str, str]:
    """Resolve DNS CNAME records for interesting subdomains.

    Only resolves subdomains with prefixes that commonly map to SaaS tools,
    to keep lookup count manageable. Returns {subdomain: cname_target}.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    candidates: list[str] = []
    for subdomain in subdomains:
        prefix = subdomain.split(".")[0].lower()
        if prefix in _CNAME_RESOLVE_PREFIXES:
            candidates.append(subdomain)
        if len(candidates) >= max_lookups:
            break

    cname_map: dict[str, str] = {}

    def _resolve_one(subdomain: str) -> tuple[str, str]:
        try:
            answers = resolver.resolve(subdomain, "CNAME")
            target = str(answers[0].target).rstrip(".")
            return subdomain, target
        except Exception:
            return subdomain, ""

    if not candidates:
        return {}

    with ThreadPoolExecutor(max_workers=min(len(candidates), 15)) as pool:
        for sub, target in pool.map(_resolve_one, candidates):
            if target:
                cname_map[sub] = target

    return cname_map


def _fetch_crt_sh(domain: str) -> list[str]:
    """Fetch subdomains from crt.sh certificate transparency logs.

    Returns unique subdomain names (CN/SAN entries) for the domain.
    Used to fingerprint technologies via CNAME prefix patterns
    (e.g., help.company.com → likely Zendesk).
    Limits to 200 most recent entries to avoid timeout on large domains.
    """
    try:
        with httpx.Client(
            timeout=httpx.Timeout(connect=5.0, read=12.0, write=5.0, pool=5.0),
            follow_redirects=True,
        ) as client:
            resp = client.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json", "limit": "200"},
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return []
            entries = resp.json()
            seen: set[str] = set()
            subdomains: list[str] = []
            for entry in entries:
                for field in ("common_name", "name_value"):
                    val = entry.get(field, "")
                    for name in val.split("\n"):
                        name = name.strip().lstrip("*.")
                        if name and name not in seen and not name.startswith("@"):
                            seen.add(name)
                            subdomains.append(name)
            return subdomains
    except Exception:
        return []


def _fetch_cert_issuer(domain: str) -> str:
    """Get SSL certificate issuer organization."""
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            __import__("socket").create_connection((domain, 443), timeout=5),
            server_hostname=domain,
        ) as sock:
            cert = sock.getpeercert()
            if cert:
                issuer = cert.get("issuer", ())
                for field_set in issuer:
                    for key, val in field_set:
                        if key == "organizationName":
                            return val
    except Exception:
        pass
    return ""


def collect(
    domain: str,
    skip_dns: bool = False,
    skip_cert: bool = False,
    skip_crt: bool = False,
    deep: bool = False,
) -> Evidence:
    """Collect all evidence for a domain.

    Phase 1 (parallel): HTTP main page, robots.txt, DNS TXT, TLS cert, crt.sh subdomains.
    Phase 2 (after crt.sh): DNS CNAME resolution for interesting subdomains.
    """
    with ThreadPoolExecutor(max_workers=5) as pool:
        http_fut = pool.submit(_fetch_http, domain)
        robots_fut = pool.submit(_fetch_robots_txt, domain)
        futures: dict[str, object] = {}
        if not skip_dns:
            futures["dns"] = pool.submit(_fetch_dns_txt, domain)
        if not skip_cert:
            futures["cert"] = pool.submit(_fetch_cert_issuer, domain)
        if not skip_crt:
            futures["crt"] = pool.submit(_fetch_crt_sh, domain)

        evidence = http_fut.result()

        try:
            evidence.robots_txt = robots_fut.result(timeout=10)
        except Exception:
            pass

        for key, fut in futures.items():
            try:
                result = fut.result(timeout=15)  # type: ignore[union-attr]
                if key == "dns":
                    evidence.dns_txt = result
                elif key == "cert":
                    evidence.cert_issuer = result
                elif key == "crt":
                    evidence.subdomains = result
            except Exception:
                pass

    # Phase 2: resolve CNAMEs for interesting subdomains found via crt.sh
    if evidence.subdomains and not skip_crt:
        try:
            evidence.cname_map = _resolve_cnames(evidence.subdomains)
        except Exception:
            pass

    # Phase 3: deep page scanning — fetch internal subpages, merge signals
    if deep and evidence.html and not evidence.error:
        try:
            extra_html, extra_scripts = _fetch_deep_pages(domain, evidence.html)
            if extra_html:
                evidence.html += "\n" + extra_html
            if extra_scripts:
                evidence.script_sources = list(dict.fromkeys(evidence.script_sources + extra_scripts))
        except Exception:
            pass

    return evidence


def collect_batch(
    domains: list[str],
    max_workers: int = 50,
    skip_dns: bool = False,
    skip_cert: bool = False,
    skip_crt: bool = False,
    deep: bool = False,
) -> list[Evidence]:
    """Collect evidence for multiple domains concurrently."""
    results: list[Evidence] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(collect, d, skip_dns, skip_cert, skip_crt, deep): d for d in domains
        }
        for fut in as_completed(future_map):
            results.append(fut.result())

    return results
