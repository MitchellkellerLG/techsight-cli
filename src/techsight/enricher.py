"""CSV enrichment — fill missing Tech Stack column from domain detection."""

from __future__ import annotations

import csv
import sys
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

from techsight.collector import collect_batch
from techsight.detector import detect
from techsight.output import detections_to_csv_value


# Common domain column names (case-insensitive matching)
DOMAIN_COLUMNS = {"domain", "website", "company domain", "url"}
TECH_COLUMNS = {"tech stack", "technologies", "tech_stack", "company technologies"}


def _find_column(headers: list[str], candidates: set[str]) -> str | None:
    """Find first matching column name (case-insensitive)."""
    for h in headers:
        if h.lower().strip() in candidates:
            return h
    return None


def _clean_domain(raw: str) -> str:
    """Strip protocol, www, and path from a domain string."""
    d = raw.strip().lower()
    for prefix in ("https://", "http://", "www."):
        if d.startswith(prefix):
            d = d[len(prefix):]
    return d.split("/")[0].strip()


def enrich_csv(
    input_path: str,
    output_path: str | None = None,
    domain_col: str | None = None,
    tech_col: str | None = None,
    min_confidence: int = 95,
    max_workers: int = 200,
    skip_dns: bool = False,
    skip_cert: bool = False,
    skip_crt: bool = False,
    overwrite: bool = False,
    deep: bool = False,
) -> dict[str, int]:
    """Enrich a CSV file by filling missing Tech Stack values.

    Returns stats dict with counts.
    """
    console = Console(stderr=True)
    inp = Path(input_path)

    if not inp.exists():
        console.print(f"[red]File not found: {input_path}[/red]")
        sys.exit(1)

    # Read CSV
    with open(inp, encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            console.print("[red]Empty CSV or no headers[/red]")
            sys.exit(1)
        headers = list(reader.fieldnames)
        rows = list(reader)

    # Find columns
    d_col = domain_col or _find_column(headers, DOMAIN_COLUMNS)
    if not d_col:
        console.print(f"[red]No domain column found. Headers: {headers}[/red]")
        console.print("[dim]Use --domain-col to specify[/dim]")
        sys.exit(1)

    t_col = tech_col or _find_column(headers, TECH_COLUMNS)
    if not t_col:
        t_col = "Tech Stack"
        headers.append(t_col)

    console.print(f"[dim]Domain column: {d_col}[/dim]")
    console.print(f"[dim]Tech column: {t_col}[/dim]")
    console.print(f"[dim]Rows: {len(rows)}[/dim]")

    # Find rows needing enrichment
    to_enrich: list[tuple[int, str]] = []
    for i, row in enumerate(rows):
        domain = _clean_domain(row.get(d_col, ""))
        if not domain:
            continue
        existing_tech = row.get(t_col, "").strip()
        if existing_tech and existing_tech.upper() != "NA" and not overwrite:
            continue
        to_enrich.append((i, domain))

    if not to_enrich:
        console.print("[yellow]No rows need enrichment (all have Tech Stack data)[/yellow]")
        return {"total": len(rows), "skipped": len(rows), "enriched": 0, "failed": 0}

    console.print(f"[bold]Enriching {len(to_enrich)} domains...[/bold]")

    # Dedupe domains to avoid redundant fetches
    unique_domains = list(set(d for _, d in to_enrich))
    console.print(f"[dim]{len(unique_domains)} unique domains[/dim]")

    # Collect evidence in batches
    domain_results: dict[str, str] = {}

    mode_label = "deep" if deep else ("lite" if (skip_crt and skip_cert) else "standard")
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Enriching [{mode_label}]", total=len(unique_domains))

        # Process in chunks to avoid memory issues
        chunk_size = max_workers * 2
        for start in range(0, len(unique_domains), chunk_size):
            chunk = unique_domains[start : start + chunk_size]
            evidences = collect_batch(chunk, max_workers=max_workers, skip_dns=skip_dns, skip_cert=skip_cert, skip_crt=skip_crt, deep=deep)

            for ev in evidences:
                detections = detect(ev, min_confidence=min_confidence)
                domain_results[ev.domain] = detections_to_csv_value(detections)
                progress.advance(task)

    # Apply results to rows
    stats = {"total": len(rows), "skipped": len(rows) - len(to_enrich), "enriched": 0, "failed": 0}

    for i, domain in to_enrich:
        tech_value = domain_results.get(domain, "")
        if tech_value:
            rows[i][t_col] = tech_value
            stats["enriched"] += 1
        else:
            stats["failed"] += 1

    # Write output
    out_path = output_path or str(inp.with_stem(inp.stem + "-tech"))
    with open(out_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    console.print(f"\n[green]Done![/green] Output: {out_path}")
    console.print(
        f"  Enriched: {stats['enriched']} | "
        f"Skipped (had data): {stats['skipped']} | "
        f"No tech found: {stats['failed']}"
    )

    return stats
