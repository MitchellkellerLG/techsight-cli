"""Output formatting — Rich tables and JSON."""

from __future__ import annotations

import csv
import io
import json
import sys
from typing import Any

from rich.console import Console
from rich.table import Table

from techsight.detector import Detection


CATEGORIES: dict[int, str] = {
    1: "CMS", 2: "Message board", 3: "Database manager", 4: "Documentation",
    5: "Widget", 6: "Ecommerce", 7: "Photo gallery", 8: "Wiki",
    9: "Hosting panel", 10: "Analytics", 11: "Blog", 12: "Framework",
    13: "Issue tracker", 14: "Video player", 15: "Comment system",
    16: "Security", 17: "Font script", 18: "Web framework", 19: "Miscellaneous",
    20: "Editor", 21: "LMS", 22: "Web server", 23: "Cache tool",
    24: "Rich text editor", 25: "JavaScript graphics", 26: "Mobile framework",
    27: "Programming language", 28: "Operating system", 29: "Search engine",
    30: "Web mail", 31: "CDN", 32: "Marketing automation", 33: "Web server extension",
    34: "Database", 35: "Maps", 36: "Advertising", 37: "Network device",
    38: "Media server", 39: "Webcam", 41: "Payment processor",
    42: "Tag manager", 44: "CI", 45: "Control system", 46: "Remote access",
    47: "Dev tool", 48: "Network storage", 50: "Page builder",
    51: "Accounting", 52: "Cryptominer", 53: "CRM", 54: "SEO",
    55: "Accessibility", 56: "A/B testing", 57: "Email", 58: "Personalisation",
    59: "Retargeting", 60: "RUM", 61: "Cookie compliance", 62: "Loyalty/rewards",
    63: "Feature management", 64: "Segmentation", 65: "Booking/reservations",
    66: "Surveys", 67: "DMP", 68: "Chat", 69: "Cart functionality",
    70: "Cart abandonment", 71: "Customer data platform", 72: "Consent management",
    73: "Performance", 74: "ID management", 75: "Geolocation",
    76: "Affiliate", 77: "Appointment scheduling", 78: "Recruitment/staffing",
    79: "User onboarding", 80: "Reviews", 81: "Buy now pay later",
    82: "Form builder", 83: "CIAM", 84: "Live chat",
    85: "Translation", 86: "Shipping", 87: "Customer success",
    88: "Referral marketing", 89: "Digital asset management",
    90: "Content curation", 91: "Domain parking", 92: "Fundraising/donations",
    93: "Cross-border ecommerce", 94: "Fulfilment", 95: "Product recommendations",
    96: "Visual search", 97: "Customer data platform", 98: "PIM",
    99: "Digital experience platform", 100: "Session replay",
    101: "Hosting", 102: "Data governance", 103: "Tariff/duty/tax",
    104: "Web accessibility", 105: "Headless CMS",
}


def category_name(cat_id: int) -> str:
    return CATEGORIES.get(cat_id, f"Cat-{cat_id}")


def render_table(domain: str, detections: list[Detection], console: Console | None = None) -> None:
    """Render detections as a Rich table to stderr."""
    c = console or Console(stderr=True)
    table = Table(title=f"TechSight: {domain}", show_lines=False)
    table.add_column("Technology", style="bold")
    table.add_column("Category")
    table.add_column("Confidence", justify="right")
    table.add_column("Vectors")

    for d in detections:
        cats = ", ".join(category_name(c) for c in d.category_ids[:2]) if d.category_ids else ""
        conf_style = "green" if d.confidence >= 95 else "yellow" if d.confidence >= 70 else "red"
        table.add_row(
            d.name,
            cats,
            f"[{conf_style}]{d.confidence}%[/{conf_style}]",
            ", ".join(d.vectors[:3]),
        )

    c.print(table)
    c.print(f"\n[dim]{len(detections)} technologies detected[/dim]")


def render_json(domain: str, detections: list[Detection]) -> None:
    """Render detections as JSON to stdout."""
    result = {
        "domain": domain,
        "count": len(detections),
        "technologies": [
            {
                "name": d.name,
                "categories": [category_name(c) for c in d.category_ids],
                "confidence": d.confidence,
                "vectors": d.vectors,
                "website": d.website,
                **({"implied_by": d.implied_by} if d.implied_by else {}),
            }
            for d in detections
        ],
    }
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")


def detections_to_csv_value(detections: list[Detection]) -> str:
    """Convert detections to a comma-separated string for CSV Tech Stack column."""
    return ", ".join(d.name for d in detections)
