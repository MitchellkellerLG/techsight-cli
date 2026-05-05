"""Core detection engine — matches fingerprints against collected evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from techsight.signatures import TechSignature, get_signatures


@dataclass
class Evidence:
    """All collected evidence for a single domain."""

    domain: str
    url: str = ""

    # HTTP response
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)  # lowercase keys
    cookies: dict[str, str] = field(default_factory=dict)  # name -> value
    html: str = ""

    # Parsed from HTML
    script_sources: list[str] = field(default_factory=list)
    meta_tags: dict[str, str] = field(default_factory=dict)  # name -> content

    # DNS
    dns_txt: list[str] = field(default_factory=list)

    # TLS
    cert_issuer: str = ""

    # crt.sh subdomain enumeration
    subdomains: list[str] = field(default_factory=list)

    # DNS CNAME targets for interesting subdomains (subdomain → cname_target)
    cname_map: dict[str, str] = field(default_factory=dict)

    # robots.txt body
    robots_txt: str = ""

    # Error
    error: str | None = None


@dataclass
class Detection:
    """A single technology detection with confidence."""

    name: str
    category_ids: list[int]
    confidence: int  # 0-100
    vectors: list[str]  # which vectors matched
    website: str = ""
    description: str = ""
    implied_by: str | None = None  # if detected via implication


def _match_header(sig: TechSignature, evidence: Evidence) -> list[str]:
    """Check HTTP headers against signature patterns."""
    matches = []
    for header_name, pattern in sig.headers.items():
        header_val = evidence.headers.get(header_name, "")
        if not header_val:
            continue
        if pattern is None:
            # Empty pattern = header just needs to exist
            matches.append(f"header:{header_name}")
        elif pattern.search(header_val):
            matches.append(f"header:{header_name}")
    return matches


def _match_cookies(sig: TechSignature, evidence: Evidence) -> list[str]:
    """Check cookies against signature patterns."""
    matches = []
    for cookie_name_pattern, value_pattern in sig.cookies.items():
        for cookie_name, cookie_val in evidence.cookies.items():
            # Cookie name can be a regex pattern
            try:
                if re.search(cookie_name_pattern, cookie_name, re.IGNORECASE):
                    if value_pattern is None or value_pattern.search(cookie_val):
                        matches.append(f"cookie:{cookie_name}")
            except re.error:
                if cookie_name_pattern.lower() in cookie_name.lower():
                    matches.append(f"cookie:{cookie_name}")
    return matches


def _match_meta(sig: TechSignature, evidence: Evidence) -> list[str]:
    """Check meta tags against signature patterns."""
    matches = []
    for meta_name, pattern in sig.meta.items():
        meta_val = evidence.meta_tags.get(meta_name.lower(), "")
        if not meta_val:
            continue
        if pattern is None:
            matches.append(f"meta:{meta_name}")
        elif pattern.search(meta_val):
            matches.append(f"meta:{meta_name}")
    return matches


def _match_script_src(sig: TechSignature, evidence: Evidence) -> list[str]:
    """Check script src attributes against signature patterns."""
    matches = []
    for pattern in sig.script_src:
        for src in evidence.script_sources:
            if pattern.search(src):
                matches.append(f"scriptSrc:{pattern.pattern[:40]}")
                break
    return matches


def _match_html(sig: TechSignature, evidence: Evidence) -> list[str]:
    """Check HTML body against signature patterns."""
    if not evidence.html:
        return []
    matches = []
    for pattern in sig.html:
        if pattern.search(evidence.html):
            matches.append(f"html:{pattern.pattern[:40]}")
    return matches


def _match_dns(sig: TechSignature, evidence: Evidence) -> list[str]:
    """Check DNS TXT records against signature patterns."""
    matches = []
    for pattern in sig.dns_txt:
        for txt in evidence.dns_txt:
            if pattern.search(txt):
                matches.append(f"dns:{pattern.pattern[:40]}")
                break
    return matches


def _match_url(sig: TechSignature, evidence: Evidence) -> list[str]:
    """Check URL against signature patterns."""
    if not evidence.url:
        return []
    matches = []
    for pattern in sig.url_patterns:
        if pattern.search(evidence.url):
            matches.append(f"url:{pattern.pattern[:40]}")
    return matches


def _match_cert(sig: TechSignature, evidence: Evidence) -> list[str]:
    """Check certificate issuer against signature patterns."""
    if not evidence.cert_issuer:
        return []
    matches = []
    for pattern in sig.cert_issuer:
        if pattern.search(evidence.cert_issuer):
            matches.append(f"cert:{pattern.pattern[:40]}")
    return matches


# CNAME suffix → (tech_name, confidence) from crt.sh subdomain fingerprinting.
# Confidence reflects how uniquely the subdomain prefix implies the technology.
_CNAME_FINGERPRINTS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"\.salesforce\.com$", re.I), "Salesforce", 95),
    (re.compile(r"\.force\.com$", re.I), "Salesforce", 95),
    (re.compile(r"\.zendesk\.com$", re.I), "Zendesk", 95),
    (re.compile(r"\.hubspot\.com$", re.I), "HubSpot", 95),
    (re.compile(r"\.hubspot\.net$", re.I), "HubSpot", 95),
    (re.compile(r"\.intercom\.io$", re.I), "Intercom", 95),
    (re.compile(r"\.intercomcdn\.com$", re.I), "Intercom", 90),
    (re.compile(r"\.marketo\.net$", re.I), "Marketo", 95),
    (re.compile(r"\.mktocdn\.com$", re.I), "Marketo", 90),
    (re.compile(r"\.pardot\.com$", re.I), "Pardot", 95),
    (re.compile(r"\.eloqua\.com$", re.I), "Eloqua", 95),
    (re.compile(r"\.exacttarget\.com$", re.I), "Salesforce Marketing Cloud", 90),
    (re.compile(r"\.mktoweb\.com$", re.I), "Marketo", 90),
    (re.compile(r"\.drift\.com$", re.I), "Drift", 95),
    (re.compile(r"\.driftt\.com$", re.I), "Drift", 90),
    (re.compile(r"\.chilipiper\.com$", re.I), "Chili Piper", 95),
    (re.compile(r"\.outreach\.io$", re.I), "Outreach", 95),
    (re.compile(r"\.salesloft\.com$", re.I), "SalesLoft", 95),
    (re.compile(r"\.gong\.io$", re.I), "Gong", 95),
    (re.compile(r"\.chorus\.ai$", re.I), "Chorus", 95),
    (re.compile(r"\.calendly\.com$", re.I), "Calendly", 95),
    (re.compile(r"\.apollo\.io$", re.I), "Apollo", 95),
    (re.compile(r"\.zoominfo\.com$", re.I), "ZoomInfo", 95),
    (re.compile(r"\.clearbit\.com$", re.I), "Clearbit", 95),
    (re.compile(r"\.6sense\.com$", re.I), "6sense", 95),
    (re.compile(r"\.demandbase\.com$", re.I), "Demandbase", 95),
    (re.compile(r"\.rollworks\.com$", re.I), "RollWorks", 95),
    (re.compile(r"\.wpengine\.com$", re.I), "WP Engine", 95),
    (re.compile(r"\.kinsta\.cloud$", re.I), "Kinsta", 95),
    (re.compile(r"\.fastly\.net$", re.I), "Fastly", 90),
]

# Common subdomain prefixes that indicate a technology is in use
_SUBDOMAIN_PREFIXES: list[tuple[str, str, int]] = [
    ("help.", "Zendesk", 70),
    ("support.", "Zendesk", 60),
    ("go.", "Marketo", 60),
    ("pages.", "HubSpot", 65),
    ("info.", "HubSpot", 55),
    ("blog.", "HubSpot", 50),
    ("app.", "Intercom", 50),
    ("chat.", "Intercom", 55),
]


def _match_subdomains_direct(evidence: Evidence) -> list[tuple[str, str, int]]:
    """Match crt.sh subdomains + DNS CNAMEs against fingerprints.

    Priority: resolved CNAME target (high confidence) > subdomain prefix (low confidence).
    Returns list of (tech_name, vector_label, confidence).
    """
    found: dict[str, tuple[str, int]] = {}  # tech_name → (vector, max_confidence)

    # Phase 1: resolved CNAME targets (high confidence — actual DNS confirmation)
    for subdomain, cname_target in evidence.cname_map.items():
        cname_lower = cname_target.lower()
        for pattern, tech, confidence in _CNAME_FINGERPRINTS:
            if pattern.search(cname_lower):
                label = f"crt:cname:{subdomain[:50]}→{cname_target[:40]}"
                existing = found.get(tech)
                if existing is None or confidence > existing[1]:
                    found[tech] = (label, confidence)

    # Phase 2: subdomain name patterns from crt.sh (lower confidence — no DNS resolution)
    for subdomain in evidence.subdomains:
        subdomain_lower = subdomain.lower()

        # CNAME fingerprint on subdomain name itself (e.g., company.zendesk.com in certs)
        for pattern, tech, confidence in _CNAME_FINGERPRINTS:
            if pattern.search(subdomain_lower):
                label = f"crt:{subdomain[:60]}"
                existing = found.get(tech)
                if existing is None or confidence > existing[1]:
                    found[tech] = (label, confidence)

        # Prefix hints (lower confidence — generic prefixes like help./ support.)
        for prefix, tech, confidence in _SUBDOMAIN_PREFIXES:
            # Don't downgrade if we already have a higher-confidence signal
            if subdomain_lower.startswith(prefix):
                label = f"crt:{subdomain[:60]}"
                existing = found.get(tech)
                if existing is None or confidence > existing[1]:
                    found[tech] = (label, confidence)

    return [(tech, vec, conf) for tech, (vec, conf) in found.items()]


# robots.txt path/directive patterns → (tech_name, confidence)
_ROBOTS_FINGERPRINTS: list[tuple[re.Pattern[str], str, int]] = [
    # CMS platforms
    (re.compile(r"Disallow:\s*/wp-admin", re.I), "WordPress", 95),
    (re.compile(r"Disallow:\s*/wp-content", re.I), "WordPress", 90),
    (re.compile(r"Sitemap:.*wp-sitemap", re.I), "WordPress", 95),
    (re.compile(r"Disallow:\s*/user/login", re.I), "Drupal", 90),
    (re.compile(r"Disallow:\s*/sites/default", re.I), "Drupal", 90),
    (re.compile(r"Disallow:\s*/ghost/", re.I), "Ghost", 95),
    (re.compile(r"Sitemap:.*ghost", re.I), "Ghost", 90),
    (re.compile(r"Disallow:\s*/umbraco/", re.I), "Umbraco", 95),
    (re.compile(r"Disallow:\s*/typo3/", re.I), "TYPO3", 95),
    (re.compile(r"Disallow:\s*/craft/", re.I), "Craft CMS", 95),
    # E-commerce
    (re.compile(r"Disallow:\s*/cart$", re.I), "Shopify", 80),
    (re.compile(r"Sitemap:.*shopify", re.I), "Shopify", 95),
    (re.compile(r"Disallow:\s*/checkout/", re.I), "Shopify", 70),
    (re.compile(r"Sitemap:.*bigcommerce", re.I), "BigCommerce", 95),
    (re.compile(r"Disallow:\s*/magento/", re.I), "Magento", 95),
    # Marketing / CRM
    (re.compile(r"Disallow:\s*/hs-search-results", re.I), "HubSpot", 95),
    (re.compile(r"Sitemap:.*hubspot", re.I), "HubSpot", 90),
    (re.compile(r"Disallow:\s*/mkto-", re.I), "Marketo", 90),
    (re.compile(r"Disallow:\s*/pardot/", re.I), "Pardot", 95),
    # Analytics / Tag managers
    (re.compile(r"Disallow:\s*/gtm\.js", re.I), "Google Tag Manager", 90),
]


def _match_robots_direct(evidence: Evidence) -> list[tuple[str, str, int]]:
    """Match robots.txt content against fingerprint patterns.

    Returns list of (tech_name, vector_label, confidence).
    """
    if not evidence.robots_txt:
        return []

    found: dict[str, tuple[str, int]] = {}

    for pattern, tech, confidence in _ROBOTS_FINGERPRINTS:
        m = pattern.search(evidence.robots_txt)
        if m:
            label = f"robots:{m.group(0)[:50]}"
            existing = found.get(tech)
            if existing is None or confidence > existing[1]:
                found[tech] = (label, confidence)

    return [(tech, vec, conf) for tech, (vec, conf) in found.items()]


# Inline script fingerprints — unique CDN URLs or JS initialization patterns
# embedded in HTML <script> blocks (not external <script src="">).
# These are high-confidence because the patterns are specific enough to be unambiguous
# (a unique CloudFront distribution, a proprietary window.* init pattern, etc.)
_INLINE_SCRIPT_FINGERPRINTS: list[tuple[re.Pattern[str], str, int]] = [
    # Visitor identification / intent
    (re.compile(r"ddwl4m2hdecbv\.cloudfront\.net", re.I), "RB2B", 99),
    (re.compile(r"window\.reb2b\s*=\s*window\.reb2b", re.I), "RB2B", 95),
    (re.compile(r"cdn\.popt\.in/pixel\.js", re.I), "Poptin", 95),
    (re.compile(r"ws\.zoominfo\.com/pixel", re.I), "ZoomInfo WebSights", 99),
    (re.compile(r"snap\.licdn\.com/li\.lms-analytics", re.I), "LinkedIn Insight Tag", 99),
    (re.compile(r"snap\.licdn\.com/li\.lms-analytics|linkedin\.com/insight\.min\.js", re.I), "LinkedIn Insight Tag", 99),
    (re.compile(r"static\.klaviyo\.com/onsite/js/klaviyo\.js", re.I), "Klaviyo", 99),
    (re.compile(r"window\._klOnsite\s*=", re.I), "Klaviyo", 95),
    (re.compile(r"js\.hsforms\.net/forms/embed", re.I), "HubSpot Forms", 95),
    (re.compile(r"js\.hs-scripts\.com/", re.I), "HubSpot", 99),
    (re.compile(r"js\.hscta\.net/", re.I), "HubSpot", 95),
    (re.compile(r"static\.parastorage\.com|window\.__wixSiteProperties", re.I), "Wix", 90),
    (re.compile(r"cdn\.segment\.com/analytics\.js", re.I), "Segment", 99),
    (re.compile(r"window\.analytics\s*=\s*window\.analytics\s*\|\|.*segment", re.I), "Segment", 95),
    (re.compile(r"cdn\.heapanalytics\.com/js/heap", re.I), "Heap", 99),
    (re.compile(r"window\.heap\s*=\s*window\.heap\s*\|\|", re.I), "Heap", 95),
    (re.compile(r"static\.hotjar\.com/c/hotjar-", re.I), "Hotjar", 99),
    (re.compile(r"window\.hj\s*=\s*window\.hj\s*\|\|", re.I), "Hotjar", 95),
    (re.compile(r"widget\.intercom\.io/widget/", re.I), "Intercom", 99),
    (re.compile(r"window\.Intercom\s*=\s*window\.Intercom\s*\|\|", re.I), "Intercom", 95),
    (re.compile(r"js\.driftt\.com/include/", re.I), "Drift", 99),
    (re.compile(r"window\.drift\s*=\s*window\.drift\s*\|\|", re.I), "Drift", 95),
    (re.compile(r"mktdplp\.com/munchkin\.js|mktdplp\.com", re.I), "Marketo Munchkin", 99),
    (re.compile(r"assets\.adobedtm\.com/", re.I), "Adobe Experience Platform", 95),
    (re.compile(r"cdn\.cookielaw\.org/scripttemplates/otSDKStub\.js", re.I), "OneTrust", 99),
    (re.compile(r"cdn-cookieyes\.com/client_data/", re.I), "CookieYes", 99),
    (re.compile(r"js\.chilipiper\.com/", re.I), "Chili Piper", 99),
    (re.compile(r"cdn\.tolt\.io/tolt\.js", re.I), "Tolt", 99),
    (re.compile(r"js\.apollo\.io/", re.I), "Apollo", 99),
    (re.compile(r"tag\.demandbase\.com/", re.I), "Demandbase", 99),
    (re.compile(r"cdn\.6sense\.com/", re.I), "6sense", 99),
    (re.compile(r"px\.ads\.linkedin\.com/collect", re.I), "LinkedIn Ads", 95),
    (re.compile(r"connect\.facebook\.net/[^/]+/fbevents\.js", re.I), "Facebook Pixel", 99),
    (re.compile(r"window\.fbq\s*=\s*window\.fbq\s*\|\|", re.I), "Facebook Pixel", 95),
    (re.compile(r"static\.ads-twitter\.com/uwt\.js", re.I), "Twitter/X Ads", 99),
    (re.compile(r"bat\.bing\.com/bat\.js", re.I), "Microsoft Ads", 99),
    (re.compile(r"cdn\.clearbit\.com/v1/pk\.js", re.I), "Clearbit Reveal", 99),
    (re.compile(r"cdn\.rollout\.io/|window\._ro\s*=", re.I), "CloudBees Feature Management", 90),
    # Analytics
    (re.compile(r"plausible\.io/js/script", re.I), "Plausible Analytics", 99),
    (re.compile(r"manus-analytics\.com/umami", re.I), "Umami Analytics", 99),
    (re.compile(r"scripts\.simpleanalyticscdn\.com", re.I), "Simple Analytics", 99),
    (re.compile(r"cdn\.amplitude\.com/(?:libs/analytics-browser|script/)", re.I), "Amplitude", 99),
    (re.compile(r"window\.amplitude\.init\s*\(", re.I), "Amplitude", 95),
    (re.compile(r"cdn\.mixpanel\.com/libs/mixpanel", re.I), "Mixpanel", 99),
    (re.compile(r"window\.mixpanel\s*=\s*window\.mixpanel\s*\|\|", re.I), "Mixpanel", 95),
    (re.compile(r"cdn\.posthog\.com/|window\.posthog\s*=", re.I), "PostHog", 99),
    # Website builders / hosting
    (re.compile(r"manuscdn\.com/", re.I), "Manus", 99),
    (re.compile(r"manus-space-dispatcher", re.I), "Manus", 95),
    # Email / CRM / newsletters
    (re.compile(r"\.kit\.com/[a-f0-9]+/index\.js", re.I), "ConvertKit", 99),
    (re.compile(r"convertkit\.com/", re.I), "ConvertKit", 95),
    (re.compile(r"js\.beehiiv\.com/|embeds\.beehiiv\.com/", re.I), "Beehiiv", 99),
    (re.compile(r"js\.substack\.com/", re.I), "Substack", 99),
    (re.compile(r"js\.mailchimp\.com/|mc\.us[0-9]+\.list-manage\.com", re.I), "Mailchimp", 99),
    # Tracking pixels / intent
    (re.compile(r"p\.midbound\.click/", re.I), "Midbound", 99),
    (re.compile(r"js\.qualified\.com/", re.I), "Qualified", 99),
    (re.compile(r"tag\.g2crowd\.com/", re.I), "G2", 95),
    (re.compile(r"cdn\.pendo\.io/agent/static/", re.I), "Pendo", 99),
    (re.compile(r"window\.pendo\s*=\s*window\.pendo\s*\|\|", re.I), "Pendo", 95),
    (re.compile(r"cdn\.reamaze\.com/assets/reamaze", re.I), "Reamaze", 99),
    (re.compile(r"js\.hsforms\.net/", re.I), "HubSpot Forms", 99),
    (re.compile(r"cdn\.jsdelivr\.net/gh/vierless/waitless", re.I), "Waitless", 95),
    # Scheduling
    (re.compile(r"assets\.calendly\.com/", re.I), "Calendly", 99),
    (re.compile(r"calendly\.initPopupWidget\s*\(", re.I), "Calendly", 95),
    (re.compile(r'href=["\']https://calendly\.com/[^"\']{5,}["\']', re.I), "Calendly", 90),
    (re.compile(r"assets\.cal\.com/|cal\.com/embed", re.I), "Cal.com", 99),
    (re.compile(r'href=["\']https://app\.cal\.com/[^"\']{5,}["\']', re.I), "Cal.com", 90),
    # Scheduling / video
    (re.compile(r'href=["\']https://meetings\.hubspot\.com/[^"\']{3,}["\']', re.I), "HubSpot Meetings", 90),
    (re.compile(r'href=["\']https://[^"\']*\.typeform\.com/to/[^"\']{3,}["\']', re.I), "Typeform", 90),
    (re.compile(r'href=["\']https://form\.typeform\.com/to/[^"\']{3,}["\']', re.I), "Typeform", 90),
    (re.compile(r'href=["\']https://www\.loom\.com/share/[^"\']{5,}["\']', re.I), "Loom", 90),
    (re.compile(r'href=["\']https://share\.vidyard\.com/watch/[^"\']{5,}["\']', re.I), "Vidyard", 90),
    (re.compile(r'href=["\']https://[^"\']+\.vidyard\.com/[^"\']{3,}["\']', re.I), "Vidyard", 85),
]


def _match_inline_scripts_direct(evidence: Evidence) -> list[tuple[str, str, int]]:
    """Match HTML body against inline script fingerprints.

    Targets specific CDN URLs and JS init patterns unique enough to be high-confidence
    without requiring multi-signal confirmation.
    Returns list of (tech_name, vector_label, confidence).
    """
    if not evidence.html:
        return []

    found: dict[str, tuple[str, int]] = {}

    for pattern, tech, confidence in _INLINE_SCRIPT_FINGERPRINTS:
        m = pattern.search(evidence.html)
        if m:
            label = f"inline:{m.group(0)[:60]}"
            existing = found.get(tech)
            if existing is None or confidence > existing[1]:
                found[tech] = (label, confidence)

    return [(tech, vec, conf) for tech, (vec, conf) in found.items()]


# Confidence tiers based on how many INDEPENDENT vector types matched.
# Two independent signals confirming the same tech = high confidence.
# A single signal (even a strong one) = not enough for 95%+.
#
# "Independent" means from different data sources:
#   Group A (server-side): header, cookie, cert, dns
#   Group B (page content): scriptSrc, meta, html, url
# A match from Group A + Group B = 2 independent signals.
# Two matches within the same group = 1.5 (correlated but still useful).

# Each vector type is tagged with an independence group
VECTOR_GROUP: dict[str, str] = {
    "header": "server",
    "cookie": "server",
    "cert": "server",
    "dns": "dns",        # DNS is its own group — fully independent
    "crt": "crt",        # crt.sh subdomains / CNAME resolution
    "robots": "robots",  # robots.txt — independent page-level signal
    "inline": "inline",  # unique inline CDN URLs / JS init patterns (high-specificity)
    "scriptSrc": "page",
    "meta": "page",
    "html": "page",
    "url": "page",
    "implied_by": "implied",
}


def _calculate_confidence(vectors: list[str]) -> int:
    """Calculate confidence from matched vectors.

    The model:
    - 1 vector type from 1 group = 40% (single signal, could be coincidence)
    - 2+ vector types from 1 group = 65% (correlated confirmation)
    - 2 independent groups = 95% (real confirmation)
    - 3+ independent groups = 99%
    - DNS alone = 80% (companies set these intentionally, very reliable)
    - implied_by = inherits parent confidence
    """
    if not vectors:
        return 0

    # Group by vector type
    types: dict[str, int] = {}
    for v in vectors:
        vtype = v.split(":")[0]
        types[vtype] = types.get(vtype, 0) + 1

    # Check for implied (inherits parent confidence)
    if "implied_by" in types and len(types) == 1:
        return 90  # Slightly below parent

    # Count independent groups hit
    groups_hit: set[str] = set()
    for t in types:
        group = VECTOR_GROUP.get(t, "other")
        groups_hit.add(group)

    n_types = len(types)
    n_groups = len(groups_hit)

    # DNS alone is very high confidence — companies set verification records intentionally.
    # A stripe-verification= TXT record means they use Stripe. Period.
    if n_types == 1 and "dns" in types:
        count = types["dns"]
        if count >= 2:
            return 99  # Multiple DNS records = locked
        return 95  # Single DNS verification record = confirmed

    # Single vector type, single group
    if n_types == 1 and n_groups == 1:
        count = list(types.values())[0]
        # HTML-only: regex against minified JS causes coincidental substring matches.
        # Keep confidence well below typical lower threshold (70%) to prevent false positives.
        if "html" in types:
            if count >= 3:
                return 50
            if count >= 2:
                return 40
            return 25
        if count >= 3:
            return 55
        if count >= 2:
            return 50
        return 40

    # Multiple types but same group (correlated)
    if n_groups == 1:
        if n_types >= 3:
            return 75
        return 65

    # 2 independent groups = confirmed
    if n_groups == 2:
        if n_types >= 3:
            return 97
        return 95

    # 3+ independent groups = locked in
    if n_groups >= 3:
        return 99

    return 40


def detect(evidence: Evidence, min_confidence: int = 95) -> list[Detection]:
    """Run all signatures against collected evidence.

    Returns detections meeting the minimum confidence threshold.
    Merges vectors from multiple signatures with the same tech name
    (e.g., upstream + custom) before scoring.
    """
    signatures = get_signatures()

    # Collect all matches per technology name (merge upstream + custom)
    tech_matches: dict[str, list[str]] = {}
    tech_info: dict[str, TechSignature] = {}

    for sig in signatures:
        all_matches: list[str] = []
        all_matches.extend(_match_header(sig, evidence))
        all_matches.extend(_match_cookies(sig, evidence))
        all_matches.extend(_match_meta(sig, evidence))
        all_matches.extend(_match_script_src(sig, evidence))
        all_matches.extend(_match_html(sig, evidence))
        all_matches.extend(_match_dns(sig, evidence))
        all_matches.extend(_match_url(sig, evidence))
        all_matches.extend(_match_cert(sig, evidence))

        if not all_matches:
            continue

        if sig.name not in tech_matches:
            tech_matches[sig.name] = []
            tech_info[sig.name] = sig
        tech_matches[sig.name].extend(all_matches)

    # Score merged vectors and filter by confidence
    detections: list[Detection] = []
    detected_names: set[str] = set()

    for name, vectors in tech_matches.items():
        # Dedupe vectors
        unique_vectors = list(dict.fromkeys(vectors))
        confidence = _calculate_confidence(unique_vectors)
        if confidence >= min_confidence:
            sig = tech_info[name]
            detections.append(Detection(
                name=name,
                category_ids=sig.categories,
                confidence=confidence,
                vectors=unique_vectors,
                website=sig.website,
                description=sig.description,
            ))
            detected_names.add(name)

    # Resolve implications — if A is detected and implies B, add B
    implied: list[Detection] = []
    for det in detections:
        for sig in signatures:
            if sig.name == det.name:
                for imp_name in sig.implies:
                    # Strip confidence suffix from implies
                    clean_name = imp_name.split("\\;")[0]
                    if clean_name not in detected_names:
                        implied.append(Detection(
                            name=clean_name,
                            category_ids=[],
                            confidence=det.confidence,
                            vectors=[f"implied_by:{det.name}"],
                            implied_by=det.name,
                        ))
                        detected_names.add(clean_name)
                break

    detections.extend(implied)

    def _inject_direct_hits(
        hits: list[tuple[str, str, int]],
    ) -> None:
        for tech_name, vector_label, hit_confidence in hits:
            if tech_name not in detected_names and hit_confidence >= min_confidence:
                detections.append(Detection(
                    name=tech_name,
                    category_ids=[],
                    confidence=hit_confidence,
                    vectors=[vector_label],
                ))
                detected_names.add(tech_name)
            elif tech_name in detected_names:
                for det in detections:
                    if det.name == tech_name and vector_label not in det.vectors:
                        det.vectors.append(vector_label)
                        recalculated = _calculate_confidence(det.vectors)
                        det.confidence = min(99, max(recalculated, hit_confidence))
                        break

    _inject_direct_hits(_match_subdomains_direct(evidence))
    _inject_direct_hits(_match_robots_direct(evidence))
    _inject_direct_hits(_match_inline_scripts_direct(evidence))

    detections.sort(key=lambda d: (-d.confidence, d.name))
    return detections
