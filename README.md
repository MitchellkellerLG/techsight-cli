# TechSight

Free tech stack detection CLI. Identifies 7,500+ technologies from HTTP headers, cookies, meta tags, script sources, HTML patterns, DNS TXT records, and TLS certificates. No API keys required.

## Install

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Scan a single domain
techsight scan hubspot.com

# JSON output
techsight scan hubspot.com -j

# Enrich a CSV (fill missing Tech Stack column)
techsight enrich -i leads.csv -o leads-enriched.csv

# Batch scan
techsight batch domain1.com domain2.com

# Show signature stats
techsight stats
```

## Detection Vectors

| Vector | Signal Source | Confidence |
|--------|-------------|------------|
| DNS TXT | SPF, DKIM, verification tokens | 99% |
| HTTP Headers | Server, X-Powered-By, custom headers | 95% |
| Cookies | Session cookie names | 95% |
| Meta Tags | `<meta name="generator">` | 95% |
| Script Sources | `<script src="">` CDN patterns | 85% |
| HTML Patterns | Body content regex | 70% |
| TLS Certificate | Issuer organization | 95% |

Default confidence threshold: 95%. Requires 2+ independent signal types.

## Detection Database

Powered by [WebAppAnalyzer](https://github.com/AliasIO/wappalyzer) community detection signatures (MIT licensed). 7,500+ technologies across 100+ categories.

## CSV Enrichment

Reads a CSV with a domain column, scans each domain, and fills the Tech Stack column:

```bash
techsight enrich -i companies.csv --domain-col "Website" --tech-col "Tech Stack"
```

- Skips rows that already have tech stack data (use `--overwrite` to replace)
- 50 concurrent requests by default (`--max-workers`)
- Deduplicates domains to avoid redundant fetches
