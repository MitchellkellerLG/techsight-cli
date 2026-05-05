"""TechSight CLI — free tech stack detection for 7,500+ technologies."""

from __future__ import annotations

import json
import sys
import time

import click

from techsight import __version__

_MODE_HELP = "lite: homepage+DNS only, fast (~0.15s/domain). deep: all vectors + 10 subpages (~0.35s/domain)."


def _apply_mode(mode: str | None, skip_dns: bool, skip_cert: bool, skip_crt: bool, deep: bool) -> tuple[bool, bool, bool, bool]:
    """Apply mode preset over individual skip flags. Returns (skip_dns, skip_cert, skip_crt, deep)."""
    if mode == "lite":
        skip_crt = True
        skip_cert = True
        deep = False
    elif mode == "deep":
        skip_crt = False
        skip_cert = False
        skip_dns = False
        deep = True
    return skip_dns, skip_cert, skip_crt, deep


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
@click.option("--skip-crt", is_flag=True, help="Skip crt.sh subdomain fingerprinting")
@click.option("--deep", is_flag=True, help="Scan up to 10 internal subpages (finds GTM tools on /demo, /pricing, etc.)")
@click.option("--mode", type=click.Choice(["lite", "deep"]), default=None, help=_MODE_HELP)
def scan(
    domain: str,
    json_output: bool,
    min_confidence: int,
    skip_dns: bool,
    skip_cert: bool,
    skip_crt: bool,
    deep: bool,
    mode: str | None,
) -> None:
    """Scan a single domain for technologies."""
    from techsight.collector import collect
    from techsight.detector import detect
    from techsight.output import render_json, render_table

    skip_dns, skip_cert, skip_crt, deep = _apply_mode(mode, skip_dns, skip_cert, skip_crt, deep)
    evidence = collect(domain, skip_dns=skip_dns, skip_cert=skip_cert, skip_crt=skip_crt, deep=deep)

    if evidence.error:
        click.echo(f"Warning: {evidence.error}", err=True)

    detections = detect(evidence, min_confidence=min_confidence)

    from techsight.output import _filter_subdomains
    interesting = _filter_subdomains(evidence.subdomains, domain)

    if json_output:
        render_json(domain, detections, subdomains=interesting)
    else:
        render_table(domain, detections, subdomains=interesting)


@cli.command()
@click.argument("domains", nargs=-1, required=True)
@click.option("--min-confidence", "-c", default=95, help="Minimum confidence threshold (0-100)")
@click.option("--max-workers", "-w", default=200, help="Concurrent requests")
@click.option("--skip-dns", is_flag=True, help="Skip DNS TXT lookups")
@click.option("--skip-crt", is_flag=True, help="Skip crt.sh subdomain fingerprinting")
@click.option("--deep", is_flag=True, help="Scan up to 10 internal subpages per domain")
@click.option("--mode", type=click.Choice(["lite", "deep"]), default=None, help=_MODE_HELP)
def batch(
    domains: tuple[str, ...],
    min_confidence: int,
    max_workers: int,
    skip_dns: bool,
    skip_crt: bool,
    deep: bool,
    mode: str | None,
) -> None:
    """Scan multiple domains. Output JSON to stdout."""
    from techsight.collector import collect_batch
    from techsight.detector import detect
    from techsight.output import category_name

    skip_dns, skip_cert, skip_crt, deep = _apply_mode(mode, False, False, skip_crt, deep)
    evidences = collect_batch(list(domains), max_workers=max_workers, skip_dns=skip_dns, skip_cert=skip_cert, skip_crt=skip_crt, deep=deep)

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
@click.option("--max-workers", "-w", default=200, help="Concurrent requests")
@click.option("--skip-dns", is_flag=True, help="Skip DNS TXT lookups")
@click.option("--skip-crt", is_flag=True, help="Skip crt.sh subdomain fingerprinting")
@click.option("--overwrite", is_flag=True, help="Overwrite existing tech stack values")
@click.option("--deep", is_flag=True, help="Scan up to 10 internal subpages per domain")
@click.option("--mode", type=click.Choice(["lite", "deep"]), default=None, help=_MODE_HELP)
def enrich(
    input_path: str,
    output_path: str | None,
    domain_col: str | None,
    tech_col: str | None,
    min_confidence: int,
    max_workers: int,
    skip_dns: bool,
    skip_crt: bool,
    overwrite: bool,
    deep: bool,
    mode: str | None,
) -> None:
    """Enrich a CSV by filling missing Tech Stack from domain scanning."""
    from techsight.enricher import enrich_csv

    skip_dns, skip_cert, skip_crt, deep = _apply_mode(mode, skip_dns, False, skip_crt, deep)
    enrich_csv(
        input_path=input_path,
        output_path=output_path,
        domain_col=domain_col,
        tech_col=tech_col,
        min_confidence=min_confidence,
        max_workers=max_workers,
        skip_dns=skip_dns,
        skip_cert=skip_cert,
        skip_crt=skip_crt,
        overwrite=overwrite,
        deep=deep,
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


@cli.command()
@click.option("--input", "-i", "input_path", required=True, help="Input CSV file")
@click.option("--sample", default=100, help="Number of domains to sample for benchmarking")
@click.option("--workers", "workers_str", default="50,100,150,200", help="Comma-separated worker counts to test")
@click.option("--modes", "modes_str", default="lite,deep", help="Comma-separated modes to test (lite, deep)")
@click.option("--min-confidence", "-c", default=95, help="Minimum confidence threshold")
def benchmark(
    input_path: str,
    sample: int,
    workers_str: str,
    modes_str: str,
    min_confidence: int,
) -> None:
    """Benchmark scan performance across modes and worker counts."""
    import csv
    from pathlib import Path
    from rich.console import Console
    from rich.table import Table
    from techsight.collector import collect_batch
    from techsight.detector import detect
    from techsight.enricher import DOMAIN_COLUMNS, _find_column, _clean_domain

    console = Console()
    inp = Path(input_path)

    if not inp.exists():
        console.print(f"[red]File not found: {input_path}[/red]")
        raise SystemExit(1)

    # Parse worker counts and modes
    worker_counts = [int(w.strip()) for w in workers_str.split(",") if w.strip()]
    modes = [m.strip() for m in modes_str.split(",") if m.strip()]

    # Read CSV and extract domains
    with open(inp, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            console.print("[red]Empty CSV or no headers[/red]")
            raise SystemExit(1)
        headers = list(reader.fieldnames)
        rows = list(reader)

    d_col = _find_column(headers, DOMAIN_COLUMNS)
    if not d_col:
        console.print(f"[red]No domain column found. Headers: {headers}[/red]")
        console.print("[dim]Supported column names: domain, website, company domain, url[/dim]")
        raise SystemExit(1)

    # Deduplicate and sample
    seen: set[str] = set()
    domains: list[str] = []
    for row in rows:
        d = _clean_domain(row.get(d_col, ""))
        if d and d not in seen:
            seen.add(d)
            domains.append(d)
        if len(domains) >= sample:
            break

    console.print(f"[bold]Benchmarking {len(domains)} domains — {len(modes)} modes × {len(worker_counts)} worker counts[/bold]\n")

    table = Table(title="TechSight Benchmark Results", show_lines=True)
    table.add_column("Mode", style="cyan")
    table.add_column("Workers", justify="right")
    table.add_column("Time (s)", justify="right")
    table.add_column("Domains/min", justify="right", style="green")
    table.add_column("Hit Rate", justify="right", style="yellow")

    for mode in modes:
        # Translate mode to skip flags
        if mode == "lite":
            skip_dns, skip_cert, skip_crt, deep = False, True, True, False
        elif mode == "deep":
            skip_dns, skip_cert, skip_crt, deep = False, False, False, True
        else:
            console.print(f"[yellow]Unknown mode '{mode}', skipping[/yellow]")
            continue

        for workers in worker_counts:
            console.print(f"[dim]Running mode={mode} workers={workers}...[/dim]")
            t0 = time.perf_counter()
            evidences = collect_batch(
                domains,
                max_workers=workers,
                skip_dns=skip_dns,
                skip_cert=skip_cert,
                skip_crt=skip_crt,
                deep=deep,
            )
            elapsed = time.perf_counter() - t0

            hits = 0
            for ev in evidences:
                detections = detect(ev, min_confidence=min_confidence)
                if detections:
                    hits += 1

            domains_per_min = (len(domains) / elapsed) * 60 if elapsed > 0 else 0
            hit_rate = (hits / len(domains) * 100) if domains else 0

            table.add_row(
                mode,
                str(workers),
                f"{elapsed:.1f}s",
                f"{domains_per_min:.0f}",
                f"{hit_rate:.1f}%",
            )
            console.print(table)
