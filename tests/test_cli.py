"""Tests for the CLI entry point."""

from __future__ import annotations

from click.testing import CliRunner

from dragonslayer.cli import cli


class TestCLI:
    """Smoke tests for CLI commands."""

    def test_help(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "VMDragonSlayer" in result.output

    def test_info(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["info"])
        assert result.exit_code == 0
        assert "Supported analysis types" in result.output
        assert "vm_discovery" in result.output

    def test_scan_missing_file(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "nonexistent.exe"])
        assert result.exit_code != 0

    def test_analyze_missing_file(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["analyze", "nonexistent.exe"])
        assert result.exit_code != 0

    def test_patterns_list(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["patterns", "list"])
        assert result.exit_code == 0

    def test_scan_with_bytes(self, tmp_path):
        """Scan a minimal PE-like file."""
        pe_stub = b"MZ" + b"\x00" * 254  # minimal stub
        sample = tmp_path / "test.exe"
        sample.write_bytes(pe_stub)

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(sample)])
        assert result.exit_code == 0
        assert "VM Detected" in result.output

    def test_scan_json_output(self, tmp_path):
        sample = tmp_path / "test.bin"
        sample.write_bytes(b"\x00" * 64)

        runner = CliRunner()
        result = runner.invoke(cli, ["scan", str(sample), "--json-output"])
        assert result.exit_code == 0
        # JSON output should be parseable
        import json
        # Output contains the scan line + JSON
        lines = result.output.strip().split("\n")
        # Find first line that starts with {
        json_start = next(i for i, l in enumerate(lines) if l.strip().startswith("{"))
        json.loads("\n".join(lines[json_start:]))
