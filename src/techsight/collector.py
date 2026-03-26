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


def collect(domain: str, skip_dns: bool = False, skip_cert: bool = False) -> Evidence:
    """Collect all evidence for a domain.

    Fetches HTTP, DNS TXT, and TLS cert data in parallel.
    """
    evidence = _fetch_http(domain)

    # Fetch DNS and cert in parallel
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {}
        if not skip_dns:
            futures["dns"] = pool.submit(_fetch_dns_txt, domain)
        if not skip_cert:
            futures["cert"] = pool.submit(_fetch_cert_issuer, domain)

        for key, fut in futures.items():
            try:
                result = fut.result(timeout=DNS_TIMEOUT + 2)
                if key == "dns":
                    evidence.dns_txt = result
                elif key == "cert":
                    evidence.cert_issuer = result
            except Exception:
                pass

    return evidence


def collect_batch(
    domains: list[str],
    max_workers: int = 50,
    skip_dns: bool = False,
    skip_cert: bool = False,
) -> list[Evidence]:
    """Collect evidence for multiple domains concurrently."""
    results: list[Evidence] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(collect, d, skip_dns, skip_cert): d for d in domains
        }
        for fut in as_completed(future_map):
            results.append(fut.result())

    return results
