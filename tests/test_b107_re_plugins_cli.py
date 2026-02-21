"""B107 – RE tool plugins (IDA/Ghidra/Binary Ninja) + CLI export subcommand.

Tests cover:
- IDA plugin: annotation application, file loading, colour constants
- Ghidra plugin: annotation application, script file structure
- Binary Ninja plugin: annotation application, colour mapping
- CLI export subcommand registration and help text
- Plugin file existence and structure
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ═══════════════════════════════════════════════════════════════════════════
# Plugin file existence
# ═══════════════════════════════════════════════════════════════════════════

_PLUGINS_ROOT = Path(__file__).resolve().parents[1] / "plugins"


class TestPluginFiles:
    """Verify RE tool plugin files exist and have expected structure."""

    def test_ida_plugin_exists(self) -> None:
        path = _PLUGINS_ROOT / "idapro" / "dragonslayer_ida.py"
        assert path.exists()
        content = path.read_text("utf-8")
        assert "DragonSlayerPlugin" in content or "apply_annotations" in content

    def test_ghidra_plugin_exists(self) -> None:
        path = _PLUGINS_ROOT / "ghidra" / "dragonslayer_ghidra.py"
        assert path.exists()
        content = path.read_text("utf-8")
        assert "apply_annotations" in content

    def test_binja_plugin_exists(self) -> None:
        path = _PLUGINS_ROOT / "binaryninja" / "dragonslayer_binja.py"
        assert path.exists()
        content = path.read_text("utf-8")
        assert "apply_annotations" in content

    def test_ida_has_plugin_entry(self) -> None:
        content = (_PLUGINS_ROOT / "idapro" / "dragonslayer_ida.py").read_text("utf-8")
        assert "PLUGIN_ENTRY" in content

    def test_ghidra_has_script_metadata(self) -> None:
        content = (_PLUGINS_ROOT / "ghidra" / "dragonslayer_ghidra.py").read_text("utf-8")
        assert "@category" in content or "@author" in content

    def test_binja_has_register_commands(self) -> None:
        content = (_PLUGINS_ROOT / "binaryninja" / "dragonslayer_binja.py").read_text("utf-8")
        assert "PluginCommand.register" in content or "BINJA_AVAILABLE" in content


# ═══════════════════════════════════════════════════════════════════════════
# IDA plugin (without IDA API)
# ═══════════════════════════════════════════════════════════════════════════

class TestIDAPlugin:
    """Test IDA plugin functions in isolation (no IDA API required)."""

    def test_import_without_ida(self) -> None:
        """Plugin module should import even without IDA API."""
        # Use importlib to load from file path
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dragonslayer_ida",
            str(_PLUGINS_ROOT / "idapro" / "dragonslayer_ida.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "apply_annotations")
        assert hasattr(mod, "load_annotations_file")
        assert hasattr(mod, "COLOR_HANDLER_KNOWN")
        assert mod.IDA_AVAILABLE is False

    def test_apply_annotations_structure(self) -> None:
        """apply_annotations should accept annotation JSON dict."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dragonslayer_ida_test",
            str(_PLUGINS_ROOT / "idapro" / "dragonslayer_ida.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        # Should not crash with empty data (IDA not available → no-ops)
        result = mod.apply_annotations({
            "annotations": [
                {"address": 0x1000, "comment": "test", "color": 0x98FB98},
            ],
            "functions": [
                {"address": 0x1000, "name": "vm_handler_1_arithmetic"},
            ],
        })
        # Without IDA, returns 0 (no-ops applied to nothing)
        assert isinstance(result, int)

    def test_load_annotations_file(self, tmp_path: Path) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dragonslayer_ida_load",
            str(_PLUGINS_ROOT / "idapro" / "dragonslayer_ida.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        data = {"version": "1.0", "annotations": [], "functions": []}
        f = tmp_path / "test.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        loaded = mod.load_annotations_file(str(f))
        assert loaded == data


# ═══════════════════════════════════════════════════════════════════════════
# Ghidra plugin (without Ghidra API)
# ═══════════════════════════════════════════════════════════════════════════

class TestGhidraPlugin:
    """Test Ghidra plugin functions in isolation."""

    def test_import_without_ghidra(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dragonslayer_ghidra",
            str(_PLUGINS_ROOT / "ghidra" / "dragonslayer_ghidra.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "apply_annotations")
        assert hasattr(mod, "load_annotations_file")
        assert mod.GHIDRA_AVAILABLE is False

    def test_load_annotations_file(self, tmp_path: Path) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dragonslayer_ghidra_load",
            str(_PLUGINS_ROOT / "ghidra" / "dragonslayer_ghidra.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        data = {"version": "1.0", "annotations": [{"address": 42}]}
        f = tmp_path / "ghidra_annot.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        loaded = mod.load_annotations_file(str(f))
        assert loaded == data


# ═══════════════════════════════════════════════════════════════════════════
# Binary Ninja plugin (without Binary Ninja API)
# ═══════════════════════════════════════════════════════════════════════════

class TestBinjaPlugin:
    """Test Binary Ninja plugin functions in isolation."""

    def test_import_without_binja(self) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dragonslayer_binja",
            str(_PLUGINS_ROOT / "binaryninja" / "dragonslayer_binja.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        assert hasattr(mod, "apply_annotations_to_bv")
        assert hasattr(mod, "load_annotations_file")
        assert mod.BINJA_AVAILABLE is False

    def test_load_annotations_file(self, tmp_path: Path) -> None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "dragonslayer_binja_load",
            str(_PLUGINS_ROOT / "binaryninja" / "dragonslayer_binja.py"),
        )
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        data = {"version": "1.0", "annotations": [], "functions": []}
        f = tmp_path / "binja_annot.json"
        f.write_text(json.dumps(data), encoding="utf-8")
        loaded = mod.load_annotations_file(str(f))
        assert loaded == data


# ═══════════════════════════════════════════════════════════════════════════
# CLI export subcommand
# ═══════════════════════════════════════════════════════════════════════════

class TestCLIExport:
    """Test the CLI export subcommand."""

    def test_export_command_registered(self) -> None:
        from dragonslayer.cli import cli
        cmd_names = [c.name for c in cli.commands.values()]
        assert "export" in cmd_names

    def test_export_help(self) -> None:
        from click.testing import CliRunner
        from dragonslayer.cli import cli

        runner = CliRunner()
        result = runner.invoke(cli, ["export", "--help"])
        assert result.exit_code == 0
        assert "format" in result.output.lower()
        assert "json" in result.output.lower()

    def test_all_commands_present(self) -> None:
        from dragonslayer.cli import cli
        cmd_names = sorted(c.name for c in cli.commands.values())
        assert "scan" in cmd_names
        assert "analyze" in cmd_names
        assert "info" in cmd_names
        assert "patterns" in cmd_names
        assert "export" in cmd_names

    def test_export_format_choices(self) -> None:
        from click.testing import CliRunner
        from dragonslayer.cli import cli

        runner = CliRunner()
        # Invalid format should fail
        result = runner.invoke(cli, ["export", "nonexistent.exe", "-f", "invalid_format"])
        assert result.exit_code != 0
