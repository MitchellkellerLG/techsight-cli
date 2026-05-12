"""Basic smoke tests for TechSight CLI — imports, signatures, and CLI structure.

These tests verify that core modules load correctly and that the signature
database is present and parseable. No network access required.
"""

from __future__ import annotations

import re

from click.testing import CliRunner


class TestImports:
    """Verify all core modules import without errors."""

    def test_import_version(self) -> None:
        from techsight import __version__

        assert __version__ == "0.1.0"

    def test_import_signatures(self) -> None:
        from techsight.signatures import TechSignature, get_signatures

        assert TechSignature is not None
        assert callable(get_signatures)

    def test_import_detector(self) -> None:
        from techsight.detector import Detection, Evidence, detect

        assert Detection is not None
        assert Evidence is not None
        assert callable(detect)

    def test_import_collector(self) -> None:
        from techsight.collector import collect, collect_batch

        assert callable(collect)
        assert callable(collect_batch)

    def test_import_output(self) -> None:
        from techsight.output import detections_to_csv_value, render_json, render_table

        assert callable(detections_to_csv_value)
        assert callable(render_json)
        assert callable(render_table)

    def test_import_enricher(self) -> None:
        from techsight.enricher import enrich_csv

        assert callable(enrich_csv)

    def test_import_cli(self) -> None:
        from techsight.cli import cli

        assert cli is not None


class TestSignatures:
    """Verify the signature database loads correctly."""

    def test_signatures_load(self) -> None:
        from techsight.signatures import get_signatures

        sigs = get_signatures()
        assert len(sigs) > 0, "Signature database should not be empty"
        assert len(sigs) > 100, f"Expected >100 signatures, got {len(sigs)}"

    def test_signatures_have_names(self) -> None:
        from techsight.signatures import get_signatures

        sigs = get_signatures()
        for sig in sigs:
            assert sig.name, "Signature missing name"
            assert isinstance(sig.name, str)

    def test_signatures_have_categories(self) -> None:
        from techsight.signatures import get_signatures

        sigs = get_signatures()
        categories = {cid for sig in sigs for cid in sig.categories}
        assert len(categories) > 0, "Signatures should have categories"


class TestCLI:
    """Verify CLI commands are registered and invocable."""

    def test_cli_help(self) -> None:
        from techsight.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "batch" in result.output
        assert "enrich" in result.output
        assert "stats" in result.output

    def test_stats_command(self) -> None:
        from techsight.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["stats"])
        assert result.exit_code == 0
        assert "categories" in result.output.lower() or "signatures" in result.output.lower()

    def test_scan_requires_domain(self) -> None:
        from techsight.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        # Should fail or show help because domain is required
        assert result.exit_code != 0 or "Error" in result.output or "Usage" in result.output

    def test_batch_requires_domains(self) -> None:
        from techsight.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["batch"])
        assert result.exit_code != 0 or "Usage" in result.output or "Error" in result.output

    def test_enrich_requires_input(self) -> None:
        from techsight.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["enrich"])
        assert result.exit_code != 0 or "Usage" in result.output or "Error" in result.output


class TestDetectionEngine:
    """Verify detection engine internals."""

    def test_confidence_calculation(self) -> None:
        from techsight.detector import _calculate_confidence

        # Single high-confidence vector
        assert _calculate_confidence(["dns"]) >= 90

        # Multiple vectors should increase confidence
        multi = _calculate_confidence(["dns", "header"])
        single = _calculate_confidence(["dns"])
        assert multi >= single

    def test_evidence_dataclass(self) -> None:
        from techsight.detector import Evidence

        e = Evidence(domain="example.com")
        assert e.domain == "example.com"
        assert e.html == ""
        assert e.headers == {}
        assert e.cookies == {}
        assert e.script_sources == []
        assert e.meta_tags == {}

    def test_detection_dataclass(self) -> None:
        from techsight.detector import Detection

        d = Detection(name="Test", category_ids=[1, 2], confidence=95, vectors=["dns"])
        assert d.name == "Test"
        assert d.category_ids == [1, 2]
        assert d.confidence == 95
        assert d.vectors == ["dns"]

    def test_parse_internal_links(self) -> None:
        from techsight.collector import _parse_internal_links

        html = '<a href="/about">About</a><a href="/contact">Contact</a><a href="https://other.com">External</a>'
        links = _parse_internal_links(html, "example.com")
        assert "/about" in links
        assert "/contact" in links
        assert "https://other.com" not in links

    def test_parse_script_sources(self) -> None:
        from techsight.collector import _parse_script_sources

        html = (
            '<script src="/app.js"></script><script src="https://cdn.example.com/lib.js"></script>'
        )
        sources = _parse_script_sources(html)
        assert len(sources) >= 2

    def test_parse_meta_tags(self) -> None:
        from techsight.collector import _parse_meta_tags

        html = (
            '<meta name="generator" content="WordPress">'
            '<meta name="viewport" content="width=device-width">'
        )
        tags = _parse_meta_tags(html)
        assert "generator" in tags
        assert tags["generator"] == "WordPress"

    def test_clean_domain_enricher(self) -> None:
        from techsight.enricher import _clean_domain

        assert _clean_domain("https://example.com/path") == "example.com"
        assert _clean_domain("http://www.example.com") == "example.com"
        assert _clean_domain("example.com") == "example.com"

    def test_output_category_name(self) -> None:
        from techsight.output import category_name

        result = category_name(0)
        assert isinstance(result, str)
        assert len(result) > 0


class TestRegexPatterns:
    """Verify regex signatures compile and match correctly."""

    def test_signature_regex_compiles(self) -> None:
        from techsight.signatures import get_signatures

        sigs = get_signatures()
        for sig in sigs:
            for pat in sig.script_src:
                assert isinstance(pat, re.Pattern), (
                    f"Script pattern not compiled for {sig.name}: {pat}"
                )
