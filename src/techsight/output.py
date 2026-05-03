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


# Maps WebAppAnalyzer category IDs → concise group label for AI-parseable output.
# Groups reflect what matters for GTM/sales intelligence.
_CAT_TO_GROUP: dict[int, str] = {
    # CMS / site builder
    1: "cms", 11: "cms", 50: "cms", 105: "cms", 20: "cms",
    # Hosting / infra
    9: "hosting", 22: "hosting", 28: "hosting", 37: "hosting",
    101: "hosting", 31: "cdn", 23: "cache",
    # Framework / language
    12: "framework", 18: "framework", 26: "framework", 27: "language",
    # Analytics
    10: "analytics", 60: "analytics", 100: "analytics",
    # Advertising / retargeting
    36: "advertising", 59: "retargeting", 64: "segmentation",
    # Marketing automation / email
    32: "marketing_automation", 57: "email", 84: "email",
    # CRM / sales
    53: "crm", 87: "customer_success",
    # Intent / identity
    67: "dmp", 71: "cdp", 97: "cdp",
    # Chat / support
    68: "chat", 4: "support", 13: "support",
    # Appointment / booking
    77: "scheduling", 65: "scheduling",
    # Tag management
    42: "tag_manager",
    # A/B / personalisation
    56: "ab_testing", 58: "personalisation", 63: "feature_flags",
    # Consent / compliance
    61: "consent", 72: "consent", 102: "consent",
    # Payments / ecommerce
    41: "payments", 6: "ecommerce", 69: "ecommerce", 81: "ecommerce",
    # Forms / surveys
    82: "forms", 66: "forms",
    # SEO
    54: "seo",
    # User onboarding / product
    79: "product_analytics", 80: "reviews", 88: "referral",
    # Security / ID
    16: "security", 74: "iam", 83: "iam",
    # Dev / infra
    44: "ci_cd", 47: "dev_tools", 34: "database",
}

# Tech names that belong to a specific group regardless of category (overrides/supplements)
_NAME_TO_GROUP: dict[str, str] = {
    "RB2B": "intent",
    "ZoomInfo WebSights": "intent",
    "6sense": "intent",
    "Demandbase": "intent",
    "Clearbit Reveal": "intent",
    "Clearbit": "intent",
    "Apollo": "crm",
    "LinkedIn Insight Tag": "advertising",
    "LinkedIn Ads": "advertising",
    "Facebook Pixel": "advertising",
    "Microsoft Ads": "advertising",
    "Twitter/X Ads": "advertising",
    "Google Tag Manager": "tag_manager",
    "Segment": "cdp",
    "Heap": "product_analytics",
    "Hotjar": "product_analytics",
    "Pendo": "product_analytics",
    "PostHog": "product_analytics",
    "Amplitude": "product_analytics",
    "Mixpanel": "product_analytics",
    "Intercom": "chat",
    "Drift": "chat",
    "Chili Piper": "scheduling",
    "Calendly": "scheduling",
    "Cal.com": "scheduling",
    "HubSpot": "marketing_automation",
    "HubSpot CMS Hub": "cms",
    "HubSpot Forms": "forms",
    "Marketo": "marketing_automation",
    "Marketo Munchkin": "marketing_automation",
    "Pardot": "marketing_automation",
    "Salesforce": "crm",
    "Salesforce Marketing Cloud": "marketing_automation",
    "Outreach": "sales_engagement",
    "SalesLoft": "sales_engagement",
    "Gong": "sales_engagement",
    "Chorus": "sales_engagement",
    "Plausible Analytics": "analytics",
    "Umami Analytics": "analytics",
    "Simple Analytics": "analytics",
    "ConvertKit": "email",
    "Beehiiv": "email",
    "Mailchimp": "email",
    "Klaviyo": "email",
    "SendGrid": "email",
    "Sendgrid": "email",
    "Amazon SES": "email",
    "Mailgun": "email",
    "Zendesk": "support",
    "OneTrust": "consent",
    "CookieYes": "consent",
    "Cloudflare": "cdn",
    "Fastly": "cdn",
    "Vercel": "hosting",
    "WP Engine": "hosting",
    "Kinsta": "hosting",
    "Manus": "cms",
    "Webflow": "cms",
    "Framer": "cms",
    "WordPress": "cms",
    "Shopify": "ecommerce",
    "Stripe": "payments",
    "Next.js": "framework",
    "React": "framework",
    "Midbound": "analytics",
    "Tolt": "referral",
    "Poptin": "forms",
}


def _group_detections(detections: list[Detection]) -> dict[str, list[str]]:
    """Group detected technologies by functional role."""
    groups: dict[str, list[str]] = {}
    for d in detections:
        group = _NAME_TO_GROUP.get(d.name)
        if not group:
            for cat_id in d.category_ids:
                group = _CAT_TO_GROUP.get(cat_id)
                if group:
                    break
        if not group:
            group = "other"
        groups.setdefault(group, []).append(d.name)
    return {k: v for k, v in sorted(groups.items())}


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
        "stacks": _group_detections(detections),
        "technologies": [
            {
                "name": d.name,
                "group": _NAME_TO_GROUP.get(d.name) or next(
                    (_CAT_TO_GROUP[c] for c in d.category_ids if c in _CAT_TO_GROUP), "other"
                ),
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
