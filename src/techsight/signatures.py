"""Load and parse WebAppAnalyzer detection signatures."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DATA_DIR = Path(__file__).parent / "data"

# Vectors we can match without a browser runtime
USABLE_VECTORS = {"headers", "cookies", "meta", "scriptSrc", "html", "dns", "url", "certIssuer"}


@dataclass
class TechSignature:
    """Detection signature for a single technology."""

    name: str
    categories: list[int] = field(default_factory=list)
    website: str = ""
    description: str = ""
    implies: list[str] = field(default_factory=list)

    # Detection patterns — compiled regexes grouped by vector
    headers: dict[str, re.Pattern[str] | None] = field(default_factory=dict)
    cookies: dict[str, re.Pattern[str] | None] = field(default_factory=dict)
    meta: dict[str, re.Pattern[str] | None] = field(default_factory=dict)
    script_src: list[re.Pattern[str]] = field(default_factory=list)
    html: list[re.Pattern[str]] = field(default_factory=list)
    dns_txt: list[re.Pattern[str]] = field(default_factory=list)
    url_patterns: list[re.Pattern[str]] = field(default_factory=list)
    cert_issuer: list[re.Pattern[str]] = field(default_factory=list)


def _parse_pattern(raw: str) -> tuple[re.Pattern[str] | None, str | None]:
    """Parse a Wappalyzer pattern string into a compiled regex.

    Format: 'pattern\\;version:\\1\\;confidence:50'
    Returns (compiled_regex, version_group) or (None, None) for empty patterns.
    """
    if not raw:
        return None, None

    # Strip metadata flags (;version:, ;confidence:)
    pattern_str = raw.split("\\;")[0]
    if not pattern_str:
        return None, None

    try:
        return re.compile(pattern_str, re.IGNORECASE), None
    except re.error:
        return None, None


def _parse_pattern_list(raw: str | list[str]) -> list[re.Pattern[str]]:
    """Parse a string or list of pattern strings into compiled regexes."""
    if isinstance(raw, str):
        raw = [raw]
    result = []
    for r in raw:
        pat, _ = _parse_pattern(r)
        if pat is not None:
            result.append(pat)
    return result


def _parse_pattern_dict(raw: dict[str, str] | str) -> dict[str, re.Pattern[str] | None]:
    """Parse a dict of {header_name: pattern} into compiled regexes."""
    if isinstance(raw, str):
        pat, _ = _parse_pattern(raw)
        return {"": pat}
    result: dict[str, re.Pattern[str] | None] = {}
    for key, val in raw.items():
        pat, _ = _parse_pattern(val)
        result[key.lower()] = pat
    return result


def _ensure_list(val: Any) -> list[str]:
    """Normalize a string or list to a list of strings."""
    if isinstance(val, str):
        return [val]
    if isinstance(val, list):
        return [str(v) for v in val]
    return []


def load_signatures() -> list[TechSignature]:
    """Load all technology signatures from the data directory."""
    sigs: list[TechSignature] = []

    for json_file in sorted(DATA_DIR.glob("*.json")):
        with open(json_file, encoding="utf-8") as f:
            data: dict[str, dict[str, Any]] = json.load(f)

        for name, info in data.items():
            # Skip if tech has zero usable vectors
            has_usable = any(k in info for k in USABLE_VECTORS)
            if not has_usable:
                continue

            sig = TechSignature(
                name=name,
                categories=info.get("cats", []),
                website=info.get("website", ""),
                description=info.get("description", ""),
                implies=_ensure_list(info.get("implies", [])),
            )

            if "headers" in info:
                sig.headers = _parse_pattern_dict(info["headers"])
            if "cookies" in info:
                sig.cookies = _parse_pattern_dict(info["cookies"])
            if "meta" in info:
                sig.meta = _parse_pattern_dict(info["meta"])
            if "scriptSrc" in info:
                sig.script_src = _parse_pattern_list(info["scriptSrc"])
            if "html" in info:
                sig.html = _parse_pattern_list(info["html"])
            if "dns" in info:
                dns_info = info["dns"]
                if "TXT" in dns_info:
                    sig.dns_txt = _parse_pattern_list(dns_info["TXT"])
            if "url" in info:
                sig.url_patterns = _parse_pattern_list(info["url"])
            if "certIssuer" in info:
                sig.cert_issuer = _parse_pattern_list(info["certIssuer"])

            sigs.append(sig)

    return sigs


# Module-level cache
_SIGNATURES: list[TechSignature] | None = None


def get_signatures() -> list[TechSignature]:
    """Get cached signatures (loaded once)."""
    global _SIGNATURES
    if _SIGNATURES is None:
        _SIGNATURES = load_signatures()
    return _SIGNATURES
