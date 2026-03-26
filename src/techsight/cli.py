"""TechSight CLI — free tech stack detection for 7,500+ technologies."""

from __future__ import annotations

import json
import sys

import click

from techsight import __version__


@click.group()
@click.version_option(__version__)
def cli() -> None:
    """TechSight — detect tech stacks from HTTP, DNS, and TLS signals."""


@cli.command()
@click.argument("domain")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON to stdout")
@click.option("--min-confidence", "-c", default=95, help="Minimum confidence threshold (0-100)")
@click.option("--skip-dns", is_flag=True, help="Skip DNS TXT lookups")
@click.option("--skip-cert", is_flag=True, help="Skip TLS certificate check")
def scan(
    domain: str,
    json_output: bool,
    min_confidence: int,
    skip_dns: bool,
    skip_cert: bool,
) -> None:
    """Scan a single domain for technologies."""
    from techsight.collector import collect
    from techsight.detector import detect
    from techsight.output import render_json, render_table

    evidence = collect(domain, skip_dns=skip_dns, skip_cert=skip_cert)

    if evidence.error:
        click.echo(f"Warning: {evidence.error}", err=True)

    detections = detect(evidence, min_confidence=min_confidence)

    if json_output:
        render_json(domain, detections)
    else:
        render_table(domain, detections)


@cli.command()
@click.argument("domains", nargs=-1, required=True)
@click.option("--min-confidence", "-c", default=95, help="Minimum confidence threshold (0-100)")
@click.option("--max-workers", "-w", default=50, help="Concurrent requests")
@click.option("--skip-dns", is_flag=True, help="Skip DNS TXT lookups")
def batch(
    domains: tuple[str, ...],
    min_confidence: int,
    max_workers: int,
    skip_dns: bool,
) -> None:
    """Scan multiple domains. Output JSON to stdout."""
    from techsight.collector import collect_batch
    from techsight.detector import detect
    from techsight.output import category_name

    evidences = collect_batch(list(domains), max_workers=max_workers, skip_dns=skip_dns)

    results = []
    for ev in evidences:
        detections = detect(ev, min_confidence=min_confidence)
        results.append({
            "domain": ev.domain,
            "count": len(detections),
            "technologies": [
                {
                    "name": d.name,
                    "categories": [category_name(c) for c in d.category_ids],
                    "confidence": d.confidence,
                }
                for d in detections
            ],
            "error": ev.error,
        })

    json.dump(results, sys.stdout, indent=2)
    sys.stdout.write("\n")


@cli.command()
@click.option("--input", "-i", "input_path", required=True, help="Input CSV file")
@click.option("--output", "-o", "output_path", help="Output CSV file (default: {input}-tech.csv)")
@click.option("--domain-col", help="Column name containing domains")
@click.option("--tech-col", help="Column name for tech stack output")
@click.option("--min-confidence", "-c", default=95, help="Minimum confidence threshold")
@click.option("--max-workers", "-w", default=50, help="Concurrent requests")
@click.option("--skip-dns", is_flag=True, help="Skip DNS TXT lookups")
@click.option("--overwrite", is_flag=True, help="Overwrite existing tech stack values")
def enrich(
    input_path: str,
    output_path: str | None,
    domain_col: str | None,
    tech_col: str | None,
    min_confidence: int,
    max_workers: int,
    skip_dns: bool,
    overwrite: bool,
) -> None:
    """Enrich a CSV by filling missing Tech Stack from domain scanning."""
    from techsight.enricher import enrich_csv

    enrich_csv(
        input_path=input_path,
        output_path=output_path,
        domain_col=domain_col,
        tech_col=tech_col,
        min_confidence=min_confidence,
        max_workers=max_workers,
        skip_dns=skip_dns,
        overwrite=overwrite,
    )


@cli.command()
def stats() -> None:
    """Show signature database statistics."""
    from collections import Counter
    from techsight.output import category_name
    from techsight.signatures import get_signatures

    sigs = get_signatures()
    click.echo(f"Total signatures loaded: {len(sigs)}")

    vector_counts: dict[str, int] = {
        "headers": 0, "cookies": 0, "meta": 0, "scriptSrc": 0,
        "html": 0, "dns_txt": 0, "url": 0, "certIssuer": 0,
    }
    cat_counts: Counter[str] = Counter()

    for sig in sigs:
        if sig.headers:
            vector_counts["headers"] += 1
        if sig.cookies:
            vector_counts["cookies"] += 1
        if sig.meta:
            vector_counts["meta"] += 1
        if sig.script_src:
            vector_counts["scriptSrc"] += 1
        if sig.html:
            vector_counts["html"] += 1
        if sig.dns_txt:
            vector_counts["dns_txt"] += 1
        if sig.url_patterns:
            vector_counts["url"] += 1
        if sig.cert_issuer:
            vector_counts["certIssuer"] += 1
        for cat in sig.categories:
            cat_counts[category_name(cat)] += 1

    click.echo("\nDetection vectors:")
    for vec, count in sorted(vector_counts.items(), key=lambda x: -x[1]):
        click.echo(f"  {vec:15s} {count:5d} signatures")

    click.echo(f"\nTop 15 categories:")
    for cat, count in cat_counts.most_common(15):
        click.echo(f"  {cat:30s} {count:5d}")
