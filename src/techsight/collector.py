"""Evidence collection — async HTTP, DNS, and TLS data for a domain."""

from __future__ import annotations

import asyncio
import re
import ssl
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import dns.asyncresolver
import httpx

from techsight.detector import Evidence


MAX_BODY_BYTES = 2 * 1024 * 1024  # 2MB
HTTP_TIMEOUT = 15
DNS_TIMEOUT = 5

# Subdomain prefixes to brute-force via DNS — mirrors output._INTERESTING_PREFIXES
_BRUTE_FORCE_PREFIXES = frozenset([
    "app", "portal", "dashboard", "admin", "platform", "product",
    "help", "support", "docs", "status",
    "blog", "news", "content",
    "shop", "store", "checkout",
    "api", "dev", "staging", "sandbox",
    "go", "link", "track", "email", "info", "mail", "send",
    "careers", "jobs",
    "community", "forum",
    "login", "auth", "sso",
    "marketing", "growth",
])

# Small pool for blocking cert fetches only
_CERT_POOL = ThreadPoolExecutor(max_workers=10)


def _parse_script_sources(html: str) -> list[str]:
    return re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)


def _parse_meta_tags(html: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for match in re.finditer(
        r'<meta[^>]+(?:name|property)=["\']([^"\']+)["\'][^>]+content=["\']([^"\']*)["\']',
        html,
        re.IGNORECASE,
    ):
        tags[match.group(1).lower()] = match.group(2)
    for match in re.finditer(
        r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+(?:name|property)=["\']([^"\']+)["\']',
        html,
        re.IGNORECASE,
    ):
        tags[match.group(2).lower()] = match.group(1)
    return tags


def _parse_cookies(response: httpx.Response) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for cookie in response.cookies.jar:
        cookies[cookie.name] = cookie.value or ""
    for val in response.headers.get_list("set-cookie"):
        parts = val.split(";")[0].split("=", 1)
        if len(parts) == 2:
            cookies[parts[0].strip()] = parts[1].strip()
        elif len(parts) == 1:
            cookies[parts[0].strip()] = ""
    return cookies


def _parse_internal_links(html: str, domain: str) -> list[str]:
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
            parsed = urlparse(href)
            path = parsed.path.rstrip("/")
            if path and path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


async def _fetch_http_async(domain: str, client: httpx.AsyncClient) -> Evidence:
    evidence = Evidence(domain=domain)
    try:
        response = await client.get(f"https://{domain}", timeout=HTTP_TIMEOUT)
        evidence.url = str(response.url)
        evidence.status_code = response.status_code
        evidence.headers = {k.lower(): v for k, v in response.headers.items()}
        evidence.cookies = _parse_cookies(response)
        if response.status_code < 400:
            html = response.text[:MAX_BODY_BYTES]
            evidence.html = html
            evidence.script_sources = _parse_script_sources(html)
            evidence.meta_tags = _parse_meta_tags(html)
    except Exception as e:
        evidence.error = str(e)
    return evidence


async def _fetch_robots_txt_async(domain: str, client: httpx.AsyncClient) -> str:
    try:
        resp = await client.get(f"https://{domain}/robots.txt", timeout=8)
        if resp.status_code == 200 and "text" in resp.headers.get("content-type", "text"):
            return resp.text[:50_000]
    except Exception:
        pass
    return ""


async def _fetch_dns_txt_async(domain: str) -> list[str]:
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT
        answers = await resolver.resolve(domain, "TXT")
        records = []
        for rdata in answers:
            for txt in rdata.strings:
                records.append(txt.decode("utf-8", errors="replace"))
        return records
    except Exception:
        return []


def _fetch_cert_issuer_sync(domain: str) -> str:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            __import__("socket").create_connection((domain, 443), timeout=5),
            server_hostname=domain,
        ) as sock:
            cert = sock.getpeercert()
            if cert:
                for field_set in cert.get("issuer", ()):
                    for key, val in field_set:
                        if key == "organizationName":
                            return val
    except Exception:
        pass
    return ""


async def _fetch_cert_issuer_async(domain: str) -> str:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_CERT_POOL, _fetch_cert_issuer_sync, domain)


async def _dns_brute_force_async(domain: str) -> list[str]:
    """Resolve common subdomain prefixes against DNS. Zero external dependency."""
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2

    async def _resolve_one(prefix: str) -> str | None:
        fqdn = f"{prefix}.{domain}"
        try:
            await resolver.resolve(fqdn, "A")
            return fqdn
        except Exception:
            pass
        try:
            await resolver.resolve(fqdn, "CNAME")
            return fqdn
        except Exception:
            return None

    results = await asyncio.gather(*[_resolve_one(p) for p in _BRUTE_FORCE_PREFIXES])
    return [r for r in results if r is not None]


async def _fetch_subdomains_async(domain: str) -> list[str]:
    """Multi-source subdomain fetch: crt.sh → HackerTarget → Wayback CDX.

    Tries crt.sh first. Falls back to HackerTarget then Wayback CDX if crt.sh
    returns fewer than 5 subdomains. Merges all results that were collected.
    """
    _THRESHOLD = 5
    _TIMEOUT = httpx.Timeout(connect=5.0, read=8.0, write=5.0, pool=5.0)

    all_results: list[str] = []

    async with httpx.AsyncClient(
        timeout=_TIMEOUT,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; TechSight/0.1)"},
    ) as client:

        # Source 1 — crt.sh
        crt_results: list[str] = []
        try:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": domain, "output": "json"},
                headers={"Accept": "application/json"},
            )
            if resp.status_code == 200:
                seen: set[str] = set()
                for entry in resp.json():
                    for field in ("common_name", "name_value"):
                        for name in entry.get(field, "").split("\n"):
                            name = name.strip().lstrip("*.")
                            if name and name not in seen and not name.startswith("@"):
                                seen.add(name)
                                crt_results.append(name)
        except Exception:
            pass

        all_results.extend(crt_results)
        if len(crt_results) >= _THRESHOLD:
            return all_results

        # Source 2 — HackerTarget
        ht_results: list[str] = []
        try:
            resp = await client.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain},
            )
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    parts = line.split(",", 1)
                    if parts:
                        sub = parts[0].strip()
                        if sub.endswith(f".{domain}") and sub != domain:
                            ht_results.append(sub)
        except Exception:
            pass

        all_results.extend(ht_results)
        if len(ht_results) >= _THRESHOLD:
            return list(dict.fromkeys(all_results))

        # Source 3 — Wayback CDX
        wb_results: list[str] = []
        try:
            resp = await client.get(
                "http://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "500",
                },
            )
            if resp.status_code == 200:
                rows = resp.json()
                seen_wb: set[str] = set()
                for row in rows[1:]:  # skip header row
                    try:
                        parsed = urlparse(row[0])
                        host = parsed.hostname or ""
                        if host.endswith(f".{domain}") and host not in seen_wb:
                            seen_wb.add(host)
                            wb_results.append(host)
                    except Exception:
                        pass
        except Exception:
            pass

        all_results.extend(wb_results)

    return list(dict.fromkeys(all_results))


_CNAME_RESOLVE_PREFIXES = frozenset([
    "help", "support", "go", "pages", "info", "blog", "chat", "app",
    "docs", "status", "community", "kb", "knowledge", "portal", "login",
    "mail", "email", "crm", "meetings", "book", "calendar",
])


async def _resolve_cnames_async(subdomains: list[str], max_lookups: int = 25) -> dict[str, str]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    candidates = [
        s for s in subdomains if s.split(".")[0].lower() in _CNAME_RESOLVE_PREFIXES
    ][:max_lookups]

    if not candidates:
        return {}

    async def _resolve_one(subdomain: str) -> tuple[str, str]:
        try:
            answers = await resolver.resolve(subdomain, "CNAME")
            return subdomain, str(answers[0].target).rstrip(".")
        except Exception:
            return subdomain, ""

    results = await asyncio.gather(*[_resolve_one(c) for c in candidates])
    return {sub: target for sub, target in results if target}


async def _fetch_deep_pages_async(
    domain: str,
    homepage_html: str,
    client: httpx.AsyncClient,
    max_pages: int = 10,
) -> tuple[str, list[str]]:
    paths = _parse_internal_links(homepage_html, domain)[:max_pages]
    if not paths:
        return "", []

    DEEP_TIMEOUT = httpx.Timeout(connect=3.0, read=5.0, write=3.0, pool=3.0)

    async def _fetch_one(path: str) -> tuple[str, list[str]]:
        try:
            resp = await client.get(
                f"https://{domain}{path}",
                timeout=DEEP_TIMEOUT,
            )
            if resp.status_code < 400:
                page_html = resp.text[:MAX_BODY_BYTES]
                return page_html, _parse_script_sources(page_html)
        except Exception:
            pass
        return "", []

    results = await asyncio.gather(*[_fetch_one(p) for p in paths], return_exceptions=True)

    extra_html_parts: list[str] = []
    extra_scripts: list[str] = []
    for r in results:
        if isinstance(r, Exception):
            continue
        page_html, page_scripts = r
        if page_html:
            extra_html_parts.append(page_html)
        extra_scripts.extend(page_scripts)

    return "\n".join(extra_html_parts), extra_scripts


async def _collect_async(
    domain: str,
    client: httpx.AsyncClient,
    skip_dns: bool = False,
    skip_cert: bool = False,
    skip_crt: bool = False,
    deep: bool = False,
) -> Evidence:
    """Collect all evidence for a single domain (async)."""
    coros: list = [
        _fetch_http_async(domain, client),
        _fetch_robots_txt_async(domain, client),
    ]
    slots = ["http", "robots"]

    if not skip_dns:
        coros.append(_fetch_dns_txt_async(domain))
        slots.append("dns")
    if not skip_cert:
        coros.append(_fetch_cert_issuer_async(domain))
        slots.append("cert")
    if not skip_crt:
        coros.append(_fetch_subdomains_async(domain))
        slots.append("crt")
        coros.append(_dns_brute_force_async(domain))
        slots.append("dns_brute")

    results = await asyncio.gather(*coros, return_exceptions=True)
    slot_map = dict(zip(slots, results))

    http_result = slot_map["http"]
    evidence: Evidence = (
        http_result
        if not isinstance(http_result, Exception)
        else Evidence(domain=domain, error=str(http_result))
    )

    robots = slot_map.get("robots")
    if robots and not isinstance(robots, Exception):
        evidence.robots_txt = robots

    dns_result = slot_map.get("dns")
    if dns_result and not isinstance(dns_result, Exception):
        evidence.dns_txt = dns_result

    cert = slot_map.get("cert")
    if cert and not isinstance(cert, Exception):
        evidence.cert_issuer = cert

    crt = slot_map.get("crt")
    dns_brute = slot_map.get("dns_brute")
    merged: list[str] = []
    if crt and not isinstance(crt, Exception):
        merged.extend(crt)
    if dns_brute and not isinstance(dns_brute, Exception):
        merged.extend(dns_brute)
    if merged:
        evidence.subdomains = list(dict.fromkeys(merged))

    # Phase 2: CNAME resolution
    if evidence.subdomains and not skip_crt:
        try:
            evidence.cname_map = await _resolve_cnames_async(evidence.subdomains)
        except Exception:
            pass

    # Phase 3: deep page scanning — skip Cloudflare-protected (blocks subpages)
    cf_protected = bool(evidence.headers.get("cf-ray"))
    if deep and evidence.html and not evidence.error and not cf_protected:
        try:
            extra_html, extra_scripts = await _fetch_deep_pages_async(domain, evidence.html, client)
            if extra_html:
                evidence.html += "\n" + extra_html
            if extra_scripts:
                evidence.script_sources = list(dict.fromkeys(evidence.script_sources + extra_scripts))
        except Exception:
            pass

    return evidence


async def _collect_batch_async(
    domains: list[str],
    max_workers: int = 50,
    skip_dns: bool = False,
    skip_cert: bool = False,
    skip_crt: bool = False,
    deep: bool = False,
) -> list[Evidence]:
    """Collect evidence for multiple domains concurrently (async)."""
    sem = asyncio.Semaphore(max_workers)

    async with httpx.AsyncClient(
        verify=False,
        follow_redirects=True,
        headers={"User-Agent": "Mozilla/5.0 (compatible; TechSight/0.1)"},
        limits=httpx.Limits(max_connections=None, max_keepalive_connections=max_workers),
    ) as client:
        async def _bounded(domain: str) -> Evidence:
            async with sem:
                return await _collect_async(domain, client, skip_dns, skip_cert, skip_crt, deep)

        results = await asyncio.gather(*[_bounded(d) for d in domains], return_exceptions=True)

    return [
        r if not isinstance(r, Exception) else Evidence(domain=domains[i], error=str(r))
        for i, r in enumerate(results)
    ]


# ── Public sync API — signatures unchanged, no callers need updating ──────────

def collect(
    domain: str,
    skip_dns: bool = False,
    skip_cert: bool = False,
    skip_crt: bool = False,
    deep: bool = False,
) -> Evidence:
    """Collect all evidence for a domain."""
    async def _run() -> Evidence:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; TechSight/0.1)"},
        ) as client:
            return await _collect_async(domain, client, skip_dns, skip_cert, skip_crt, deep)

    return asyncio.run(_run())


def collect_batch(
    domains: list[str],
    max_workers: int = 50,
    skip_dns: bool = False,
    skip_cert: bool = False,
    skip_crt: bool = False,
    deep: bool = False,
) -> list[Evidence]:
    """Collect evidence for multiple domains concurrently."""
    return asyncio.run(
        _collect_batch_async(domains, max_workers, skip_dns, skip_cert, skip_crt, deep)
    )
