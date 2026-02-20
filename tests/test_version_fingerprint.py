"""
B49 — VMProtect Version Fingerprinting Tests
===============================================

Tests for:
1. Version classification from dispatcher signals
2. Transform-based version discrimination
3. Pattern metadata voting
4. Section name evidence
5. Edge cases and confidence calibration
6. Module integration
"""

import pytest

from dragonslayer.analysis.pattern_analysis.version_fingerprint import (
    VMProtectVersion,
    VMProtectVersionFingerprinter,
    VersionFingerprint,
    _map_version_string,
    _extract_op,
)


@pytest.fixture
def fp():
    return VMProtectVersionFingerprinter()


# ---------------------------------------------------------------------------
# 1. Classification from dispatcher signals
# ---------------------------------------------------------------------------

class TestDispatchStyle:
    def test_jmp_favours_v2_or_early(self, fp):
        match = {"dispatch_style": "jmp", "decode_transforms": []}
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version in (VMProtectVersion.V2, VMProtectVersion.V3_EARLY)

    def test_push_ret_favours_v35plus(self, fp):
        match = {"dispatch_style": "push_ret", "decode_transforms": ["xor ecx, edx", "rol ecx, 3"]}
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version in (VMProtectVersion.V3_MID, VMProtectVersion.V3_LATE)

    def test_computed_goto_favours_v38(self, fp):
        match = {"dispatch_style": "computed_goto", "decode_transforms": ["xor", "not", "rol", "bswap"]}
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version == VMProtectVersion.V3_LATE


class TestVipDelta:
    def test_positive_delta(self, fp):
        match = {"vip_delta": 1, "dispatch_style": "jmp", "decode_transforms": []}
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version in (VMProtectVersion.V2, VMProtectVersion.V3_EARLY)

    def test_negative_delta(self, fp):
        match = {"vip_delta": -1, "dispatch_style": "push_ret", "decode_transforms": ["xor", "rol"]}
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version in (VMProtectVersion.V3_MID, VMProtectVersion.V3_LATE)


# ---------------------------------------------------------------------------
# 2. Transform-based discrimination
# ---------------------------------------------------------------------------

class TestTransformLength:
    def test_no_transforms_v2(self, fp):
        match = {"dispatch_style": "jmp", "decode_transforms": [], "vip_delta": 1}
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version == VMProtectVersion.V2

    def test_one_transform_early_v3(self, fp):
        match = {"dispatch_style": "jmp", "decode_transforms": ["xor ecx, edx"], "vip_delta": 1}
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version == VMProtectVersion.V3_EARLY

    def test_three_transforms_mid_v3(self, fp):
        match = {
            "dispatch_style": "push_ret",
            "decode_transforms": ["xor ecx, edx", "not ecx", "rol ecx, 3"],
            "vip_delta": -1,
        }
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version in (VMProtectVersion.V3_MID, VMProtectVersion.V3_LATE)

    def test_five_transforms_late(self, fp):
        match = {
            "dispatch_style": "push_ret",
            "decode_transforms": ["xor a, b", "not a", "rol a, 5", "bswap a", "mul a, b"],
            "vip_delta": -1,
            "fetch_width": 2,
        }
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version == VMProtectVersion.V3_LATE


class TestTransformOps:
    def test_bswap_indicates_late(self, fp):
        match = {
            "dispatch_style": "push_ret",
            "decode_transforms": ["xor ecx, edx", "bswap ecx"],
            "vip_delta": -1,
        }
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version == VMProtectVersion.V3_LATE

    def test_rol_indicates_mid(self, fp):
        match = {
            "dispatch_style": "push_ret",
            "decode_transforms": ["xor ecx, edx", "rol ecx, 3"],
            "vip_delta": -1,
        }
        result = fp.fingerprint(dispatcher_match=match)
        assert result.version in (VMProtectVersion.V3_MID, VMProtectVersion.V3_LATE)


# ---------------------------------------------------------------------------
# 3. Pattern metadata voting
# ---------------------------------------------------------------------------

class TestPatternVoting:
    def test_patterns_with_v35_metadata(self, fp):
        patterns = [
            {"metadata": {"vmprotect_version": "3.5+"}},
            {"metadata": {"vmprotect_version": "3.5+"}},
            {"metadata": {"vmprotect_version": "3.5+"}},
        ]
        result = fp.fingerprint(matched_patterns=patterns)
        assert result.version == VMProtectVersion.V3_MID

    def test_patterns_with_v2_metadata(self, fp):
        patterns = [
            {"metadata": {"vmprotect_version": "2.x"}},
            {"metadata": {"vmprotect_version": "2.x"}},
        ]
        result = fp.fingerprint(matched_patterns=patterns)
        assert result.version == VMProtectVersion.V2

    def test_mixed_pattern_votes(self, fp):
        """Dispatcher signals should dominate over pattern votes."""
        patterns = [
            {"metadata": {"vmprotect_version": "2.x"}},
        ]
        match = {
            "dispatch_style": "push_ret",
            "decode_transforms": ["xor", "not", "rol"],
            "vip_delta": -1,
        }
        result = fp.fingerprint(dispatcher_match=match, matched_patterns=patterns)
        # Dispatcher evidence should dominate
        assert result.version in (VMProtectVersion.V3_MID, VMProtectVersion.V3_LATE)

    def test_nested_pattern_metadata(self, fp):
        """Pattern wrapped in Match object with .pattern attribute."""
        patterns = [
            {"pattern": {"metadata": {"vmprotect_version": "3.8+"}}}
        ]
        result = fp.fingerprint(matched_patterns=patterns)
        assert result.version == VMProtectVersion.V3_LATE


# ---------------------------------------------------------------------------
# 4. Section names
# ---------------------------------------------------------------------------

class TestSectionEvidence:
    def test_vmp_section(self, fp):
        result = fp.fingerprint(binary_sections=[".vmp0", ".text"])
        assert result.confidence > 0  # some signal
        assert "vmp_section" in result.evidence


# ---------------------------------------------------------------------------
# 5. Confidence calibration
# ---------------------------------------------------------------------------

class TestConfidence:
    def test_strong_evidence_high_confidence(self, fp):
        match = {
            "dispatch_style": "push_ret",
            "decode_transforms": ["xor a, b", "not a", "rol a, 3", "bswap a"],
            "vip_delta": -1,
            "fetch_width": 2,
        }
        result = fp.fingerprint(dispatcher_match=match)
        assert result.confidence >= 0.7

    def test_weak_evidence_low_confidence(self, fp):
        match = {"dispatch_style": "jmp"}
        result = fp.fingerprint(dispatcher_match=match)
        assert result.confidence < 0.5

    def test_no_evidence_unknown(self, fp):
        result = fp.fingerprint()
        assert result.version == VMProtectVersion.UNKNOWN
        assert result.confidence == 0.0

    def test_alternative_version(self, fp):
        """When scores are close, alternative is populated."""
        match = {"dispatch_style": "jmp", "decode_transforms": ["xor ecx, edx"], "vip_delta": 1}
        result = fp.fingerprint(dispatcher_match=match)
        assert result.alternative is not None


# ---------------------------------------------------------------------------
# 6. Helper functions
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_extract_op(self):
        assert _extract_op("xor ecx, edx") == "xor"
        assert _extract_op("rol ecx, 3") == "rol"
        assert _extract_op("bswap ecx") == "bswap"
        assert _extract_op("unknown stuff") == ""

    def test_map_version_string(self):
        assert _map_version_string("2.x") == VMProtectVersion.V2
        assert _map_version_string("3.0-3.4") == VMProtectVersion.V3_EARLY
        assert _map_version_string("3.x") == VMProtectVersion.V3_EARLY
        assert _map_version_string("3.5+") == VMProtectVersion.V3_MID
        assert _map_version_string("3.8+") == VMProtectVersion.V3_LATE
        assert _map_version_string("garbage") == VMProtectVersion.UNKNOWN


# ---------------------------------------------------------------------------
# 7. Module integration
# ---------------------------------------------------------------------------

class TestIntegration:
    def test_import_from_pattern_analysis(self):
        from dragonslayer.analysis.pattern_analysis import (
            VMProtectVersionFingerprinter,
            VMProtectVersion,
            VersionFingerprint,
        )
        assert callable(VMProtectVersionFingerprinter)

    def test_fingerprint_dataclass(self):
        fp = VersionFingerprint(
            version=VMProtectVersion.V3_MID,
            version_string="3.5-3.7",
            confidence=0.85,
        )
        assert fp.version == VMProtectVersion.V3_MID
        assert fp.confidence == 0.85
