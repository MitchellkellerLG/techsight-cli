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
    "dns": "dns",       # DNS is its own group — fully independent
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
        # Multiple matches of same type bumps it slightly
        count = list(types.values())[0]
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
    detections.sort(key=lambda d: (-d.confidence, d.name))
    return detections
