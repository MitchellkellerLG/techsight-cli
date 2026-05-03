# TechSight CLI

Free tech stack detection for 7,500+ technologies via HTTP fingerprinting. No API keys. Used in outbound campaign prep to enrich lead CSVs with tech stack data before Clay or sequencing.

## Install

```bash
pip install -e ".[dev]"
```

Requires Python 3.10+. Uses `httpx`, `dnspython`, `rich`, `click`. No external API keys needed.

## Core Commands

```bash
# Single domain
techsight scan hubspot.com
techsight scan hubspot.com -j                        # JSON to stdout
techsight scan hubspot.com -c 70                     # lower confidence threshold

# Batch (JSON to stdout)
techsight batch domain1.com domain2.com domain3.com

# CSV enrichment (primary outbound use case)
techsight enrich -i leads.csv -o leads-enriched.csv
techsight enrich -i leads.csv --domain-col "Website" --tech-col "Tech Stack"
techsight enrich -i leads.csv --overwrite            # replace existing tech values
techsight enrich -i leads.csv --skip-dns             # skip DNS TXT lookups (faster)
techsight enrich -i leads.csv --skip-crt             # skip crt.sh + CNAME resolution (faster)

# Signature DB stats
techsight stats
```

## CSV Enrichment Details

**Auto-detected domain columns** (case-insensitive): `domain`, `website`, `company domain`, `url`

**Auto-detected tech columns**: `tech stack`, `technologies`, `tech_stack`, `company technologies`

If no tech column is found, one named `Tech Stack` is appended.

**Domain cleaning:** strips `https://`, `http://`, `www.`, trailing paths automatically. Raw URLs work fine as input.

**Default output:** `{input}-tech.csv` in the same directory as the input file.

**Skips rows** that already have tech stack data unless `--overwrite` is passed.

## Detection Vectors & Confidence

| Vector | Signal | Confidence |
|--------|--------|------------|
| DNS TXT | SPF, DKIM, verification tokens | 95-99% |
| DNS CNAME | Subdomain CNAME resolution (SaaS tools) | 95% |
| HTTP Headers | Server, X-Powered-By, custom headers | 95% |
| Cookies | Session cookie names | 95% |
| Meta Tags | `<meta name="generator">` | 95% |
| TLS Certificate | Issuer org | 95% |
| robots.txt | Disallow paths, Sitemap URLs (CMS/e-commerce) | 90-95% |
| Script Sources | CDN patterns in `<script src="">` | 85% |
| crt.sh subdomains | Certificate transparency subdomain names | 60-95% |
| HTML Patterns | Body content regex (hardened — 2+ required) | 25-50% |

**Default confidence threshold: 95%.** Lower to 70 for more results at cost of accuracy.

**False positive hardening:** HTML-only matches are capped at 50% (1 pattern = 25%, 2 = 40%, 3+ = 50%).
Any HTML match corroborated by a second signal type (e.g. scriptSrc) immediately jumps to 65%+.

## Performance

- **50 concurrent requests** by default (`--max-workers`)
- Deduplicates domains before scanning — 1000 rows with 300 unique domains = 300 fetches
- Processes in chunks of `max_workers * 2` to control memory
- `--skip-dns` cuts latency when DNS TXT lookup is slow or unnecessary
- `--skip-crt` skips crt.sh fetch + CNAME resolution — saves 1-2s per domain on large batches
- crt.sh is flaky (returns 502 intermittently) — CNAME detection silently no-ops on failure

## Output Format

CSV tech stack value is a comma-separated string of detected technology names:
```
HubSpot, Google Analytics, Cloudflare, React
```

JSON scan output:
```json
{
  "domain": "hubspot.com",
  "technologies": [
    {"name": "HubSpot", "categories": ["CRM"], "confidence": 99}
  ]
}
```

## Signature Database

Lives in `src/techsight/data/` as split JSON files (a.json through z.json + _custom.json). Sourced from WebAppAnalyzer community signatures (MIT). Custom overrides go in `_custom.json`. Run `techsight stats` to see vector and category breakdown.

## Gotchas

- Domains behind Cloudflare WAF may return minimal headers — confidence drops, some tech hidden
- DNS TXT lookups add ~200-500ms per domain. Use `--skip-dns` on large batches where DNS signal isn't needed
- The tool strips protocols and paths from domain inputs, but completely malformed values (e.g., LinkedIn URLs) will fail silently and show as "no tech found" in stats
- `--overwrite` replaces ALL existing tech values including manually verified ones — use carefully
- Output CSV encoding is UTF-8 (no BOM). Input supports UTF-8-sig (BOM-safe)
