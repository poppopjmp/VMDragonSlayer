"""conftest – shared fixtures for VMDragonSlayer tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

# Project root (the directory that contains pyproject.toml)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Data directories
PATTERNS_DIR = PROJECT_ROOT / "data" / "patterns"
VMPROTECT_PATTERNS = PATTERNS_DIR / "vmprotect_handlers.json"
THEMIDA_PATTERNS = PATTERNS_DIR / "themida_patterns.json"


@pytest.fixture()
def vmprotect_patterns_path() -> Path:
    """Return the path to the VMProtect handler patterns JSON."""
    assert VMPROTECT_PATTERNS.exists(), f"Missing fixture data: {VMPROTECT_PATTERNS}"
    return VMPROTECT_PATTERNS


@pytest.fixture()
def themida_patterns_path() -> Path:
    """Return the path to the Themida handler patterns JSON."""
    assert THEMIDA_PATTERNS.exists(), f"Missing fixture data: {THEMIDA_PATTERNS}"
    return THEMIDA_PATTERNS


@pytest.fixture()
def vmprotect_patterns_data(vmprotect_patterns_path: Path) -> dict:
    """Load VMProtect patterns JSON into a dict."""
    return json.loads(vmprotect_patterns_path.read_text(encoding="utf-8"))


@pytest.fixture()
def sample_pe_header() -> bytes:
    """Minimal PE-like bytes with an MZ header and a .vmp0 section name."""
    # MZ header + padding + .vmp0 section name embedded
    header = b"MZ" + b"\x00" * 60
    # Embed a VM section marker after some padding
    body = b"\x00" * 256 + b".vmp0" + b"\x00" * 256
    return header + body


@pytest.fixture()
def sample_binary_with_pattern() -> bytes:
    r"""Binary data that contains a VMP ADD handler signature.

    The VMProtect ADD pattern ``vmp_add_64_v1`` is ``48 01 ?? 48 89 ??``.
    We embed ``48 01 C0 48 89 C1`` (add rax,rax; mov rcx,rax) into a
    stream of NOPs so the recogniser can find it.
    """
    nops = b"\x90" * 128
    payload = bytes.fromhex("4801C04889C1")
    return nops + payload + nops
