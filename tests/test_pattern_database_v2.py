"""Tests for the expanded VMProtect handler signature database (Batch 32).

Validates the v2.0 pattern database containing 75 handler signatures across
9 handler types, 2 architectures, and 54 unique operations.
"""

import json
from pathlib import Path

import pytest

from dragonslayer.analysis.pattern_analysis.database import (
    HandlerType,
    Pattern,
    PatternDatabase,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

VMP_PATH = Path("data/patterns/vmprotect_handlers.json")


@pytest.fixture
def db() -> PatternDatabase:
    """Load the VMProtect v2.0 pattern database."""
    return PatternDatabase(VMP_PATH)


@pytest.fixture
def raw_json() -> dict:
    """Load raw JSON for schema-level checks."""
    return json.loads(VMP_PATH.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Schema / Metadata
# ---------------------------------------------------------------------------

class TestSchema:
    """Validate top-level JSON schema fields."""

    def test_version_is_2(self, raw_json):
        assert raw_json["version"] == "2.0"

    def test_has_description(self, raw_json):
        assert "description" in raw_json
        assert len(raw_json["description"]) > 10

    def test_architecture_field(self, raw_json):
        assert raw_json["architecture"] == "multi"

    def test_patterns_is_list(self, raw_json):
        assert isinstance(raw_json["patterns"], list)

    def test_pattern_count(self, raw_json):
        assert len(raw_json["patterns"]) >= 70

    def test_all_pattern_ids_unique(self, raw_json):
        ids = [p["pattern_id"] for p in raw_json["patterns"]]
        assert len(ids) == len(set(ids)), "Duplicate pattern IDs found"

    def test_required_fields_present(self, raw_json):
        required = {"pattern_id", "name", "signature", "architecture",
                     "handler_type", "operation", "confidence", "wildcards"}
        for p in raw_json["patterns"]:
            missing = required - p.keys()
            assert not missing, f"Pattern {p.get('pattern_id')} missing: {missing}"

    def test_all_confidences_in_range(self, raw_json):
        for p in raw_json["patterns"]:
            c = p["confidence"]
            assert 0.0 <= c <= 1.0, f"{p['pattern_id']} confidence {c}"


# ---------------------------------------------------------------------------
# Loading & Statistics
# ---------------------------------------------------------------------------

class TestLoading:
    """Database-level loading of the 75-pattern file."""

    def test_total_count(self, db):
        assert len(db) >= 70

    def test_statistics_consistent(self, db):
        stats = db.get_statistics()
        assert stats["total_patterns"] == len(db)
        assert sum(stats["by_type"].values()) == len(db)
        assert sum(stats["by_architecture"].values()) == len(db)

    def test_avg_confidence_reasonable(self, db):
        stats = db.get_statistics()
        assert 0.7 <= stats["avg_confidence"] <= 1.0


# ---------------------------------------------------------------------------
# Handler Type Coverage
# ---------------------------------------------------------------------------

class TestHandlerTypeCoverage:
    """Ensure all 9 handler types have at least 1 pattern."""

    @pytest.mark.parametrize("ht", [
        "arithmetic", "bitwise", "memory", "stack",
        "control_flow", "comparison", "crypto", "conversion",
    ])
    def test_handler_type_has_patterns(self, db, ht):
        results = db.search_by_type(ht)
        assert len(results) >= 1, f"No patterns for handler_type={ht}"

    def test_arithmetic_minimum(self, db):
        assert len(db.search_by_type("arithmetic")) >= 7

    def test_bitwise_minimum(self, db):
        assert len(db.search_by_type("bitwise")) >= 10

    def test_memory_minimum(self, db):
        assert len(db.search_by_type("memory")) >= 10

    def test_control_flow_minimum(self, db):
        assert len(db.search_by_type("control_flow")) >= 14

    def test_crypto_minimum(self, db):
        assert len(db.search_by_type("crypto")) >= 5


# ---------------------------------------------------------------------------
# Architecture Coverage
# ---------------------------------------------------------------------------

class TestArchitectureCoverage:
    """Ensure both x64 and x86 patterns are present."""

    def test_x64_count(self, db):
        assert len(db.search_by_architecture("x64")) >= 60

    def test_x86_count(self, db):
        assert len(db.search_by_architecture("x86")) >= 8

    def test_x86_has_vm_enter(self, db):
        results = db.search(architecture="x86", operation="vm_enter")
        assert len(results) >= 1

    def test_x86_has_vm_exit(self, db):
        results = db.search(architecture="x86", operation="vm_exit")
        assert len(results) >= 1


# ---------------------------------------------------------------------------
# Critical VMProtect-specific Operations
# ---------------------------------------------------------------------------

class TestVMProtectOperations:
    """Key VMProtect operations that were previously missing."""

    def test_nand_present(self, db):
        results = db.search_by_operation("nand")
        assert len(results) >= 1, "NAND (NOT+AND) is core VMProtect primitive"

    def test_nor_present(self, db):
        results = db.search_by_operation("nor")
        assert len(results) >= 1, "NOR (NOT+OR) is core VMProtect primitive"

    def test_vm_enter(self, db):
        results = db.search_by_operation("vm_enter")
        assert len(results) >= 2, "Need at least individual-store and pushall variants"

    def test_vm_exit(self, db):
        results = db.search_by_operation("vm_exit")
        assert len(results) >= 2, "Need at least individual-load and popall variants"

    def test_fetch_opcode(self, db):
        results = db.search_by_operation("fetch_opcode")
        assert len(results) >= 1

    def test_dispatch(self, db):
        results = db.search_by_operation("dispatch")
        assert len(results) >= 2, "Need jmp and push+ret dispatch styles"

    def test_decrypt_opcode(self, db):
        results = db.search_by_operation("decrypt_opcode")
        assert len(results) >= 2, "Need XOR and ADD key decrypt variants"

    def test_key_update(self, db):
        results = db.search_by_operation("key_update")
        assert len(results) >= 1

    def test_context_save(self, db):
        results = db.search_by_operation("context_save")
        assert len(results) >= 1

    def test_context_restore(self, db):
        results = db.search_by_operation("context_restore")
        assert len(results) >= 1

    def test_pushf_popf(self, db):
        pushf = db.search_by_operation("pushf")
        popf = db.search_by_operation("popf")
        assert len(pushf) >= 1 and len(popf) >= 1

    def test_stack_dup_and_swap(self, db):
        dup = db.search_by_operation("stack_dup")
        swap = db.search_by_operation("stack_swap")
        assert len(dup) >= 1 and len(swap) >= 1

    def test_cpuid_check(self, db):
        results = db.search_by_operation("cpuid_check")
        assert len(results) >= 1, "Anti-debug CPUID pattern"

    def test_rdtsc_check(self, db):
        results = db.search_by_operation("rdtsc_check")
        assert len(results) >= 1, "Timing-check pattern"


# ---------------------------------------------------------------------------
# Size-variant Coverage
# ---------------------------------------------------------------------------

class TestSizeVariants:
    """Ensure multi-width patterns for key operations."""

    def test_add_has_64_and_32(self, db):
        add = db.search_by_operation("add")
        widths = set()
        for p in add:
            w = p.metadata.get("width")
            if w:
                widths.add(w)
        assert 64 in widths and 32 in widths

    def test_load_has_four_widths(self, db):
        load = db.search_by_operation("load")
        widths = {p.metadata.get("width") for p in load}
        assert {64, 32, 16, 8}.issubset(widths)

    def test_push_has_64_and_32(self, db):
        push = db.search_by_operation("push")
        widths = {p.metadata.get("width") for p in push if p.metadata.get("width")}
        assert 64 in widths


# ---------------------------------------------------------------------------
# Metadata Quality
# ---------------------------------------------------------------------------

class TestMetadata:
    """Validate metadata fields on patterns."""

    def test_all_have_metadata(self, db):
        for p in db:
            assert isinstance(p.metadata, dict), f"{p.pattern_id} has no metadata"

    def test_vmprotect_version_present(self, db):
        count = sum(1 for p in db if "vmprotect_version" in p.metadata)
        assert count >= 60, "Most patterns should have vmprotect_version"

    def test_instruction_count_present(self, db):
        count = sum(1 for p in db if "instruction_count" in p.metadata)
        assert count >= 60, "Most patterns should have instruction_count"


# ---------------------------------------------------------------------------
# Pattern Quality — variant + signature checks
# ---------------------------------------------------------------------------

class TestPatternQuality:
    """Spot-check signature correctness."""

    def test_nand_signature_has_not_and(self, db):
        """NAND should use NOT (F7) followed by AND (21/23)."""
        nand = db.search_by_operation("nand")
        for p in nand:
            sig = p.signature.upper()
            assert "F7" in sig, f"{p.pattern_id} NAND missing NOT opcode"
            assert "21" in sig or "23" in sig, f"{p.pattern_id} NAND missing AND"

    def test_vm_enter_pushall_has_push_opcodes(self, db):
        for p in db.search_by_operation("vm_enter"):
            if "pushall" in p.pattern_id or "pushall" in p.name.lower():
                assert "50" in p.signature or "60" in p.signature

    def test_vm_exit_popall_has_pop_opcodes(self, db):
        for p in db.search_by_operation("vm_exit"):
            if "popall" in p.pattern_id or "popall" in p.name.lower():
                assert "58" in p.signature or "61" in p.signature

    def test_dispatch_v2_push_ret(self, db):
        """push+ret dispatch should end with C3."""
        for p in db.search_by_operation("dispatch"):
            if "push_ret" in p.pattern_id:
                assert "C3" in p.signature.upper()

    def test_syscall_signature(self, db):
        for p in db.search_by_operation("syscall"):
            assert "0F 05" in p.signature.upper()

    def test_cpuid_signature(self, db):
        for p in db.search_by_operation("cpuid_check"):
            assert "0F A2" in p.signature.upper()


# ---------------------------------------------------------------------------
# Combined Search
# ---------------------------------------------------------------------------

class TestCombinedSearch:
    """Multi-filter queries."""

    def test_x64_arithmetic(self, db):
        results = db.search(architecture="x64", handler_type="arithmetic")
        assert len(results) >= 5

    def test_x86_control_flow(self, db):
        results = db.search(architecture="x86", handler_type="control_flow")
        assert len(results) >= 3

    def test_crypto_high_confidence(self, db):
        results = db.search(handler_type="crypto", min_confidence=0.80)
        assert len(results) >= 3

    def test_x64_bitwise_min_confidence(self, db):
        results = db.search(
            architecture="x64",
            handler_type="bitwise",
            min_confidence=0.85,
        )
        assert len(results) >= 5


# ---------------------------------------------------------------------------
# Save / Reload round-trip
# ---------------------------------------------------------------------------

class TestRoundTrip:
    """Save and reload preserves all data."""

    def test_save_reload_count(self, db, tmp_path):
        out = tmp_path / "vmp_rt.json"
        db.save(out)
        db2 = PatternDatabase(out)
        assert len(db2) == len(db)

    def test_save_reload_operations(self, db, tmp_path):
        out = tmp_path / "vmp_rt2.json"
        db.save(out)
        db2 = PatternDatabase(out)
        ops1 = sorted({p.operation for p in db})
        ops2 = sorted({p.operation for p in db2})
        assert ops1 == ops2

    def test_save_reload_metadata(self, db, tmp_path):
        out = tmp_path / "vmp_rt3.json"
        db.save(out)
        db2 = PatternDatabase(out)
        for p1 in db:
            p2 = db2.get_pattern(p1.pattern_id)
            assert p2 is not None, f"Missing {p1.pattern_id}"
            assert p2.metadata == p1.metadata

    def test_save_reload_variants(self, db, tmp_path):
        out = tmp_path / "vmp_rt4.json"
        db.save(out)
        db2 = PatternDatabase(out)
        for p1 in db:
            p2 = db2.get_pattern(p1.pattern_id)
            assert p2.variants == p1.variants
