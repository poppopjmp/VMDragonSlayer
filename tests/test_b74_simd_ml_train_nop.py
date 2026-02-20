"""B74 tests: SIMD byte taint, ML train+classify, reversed scale*index,
second NOP-stripping pass, dynamic ByteTaintMap sizes."""

from __future__ import annotations

import pytest

from dragonslayer.analysis.taint_tracking.tracker import (
    TaintTracker,
    TaintTag,
    ByteTaintMap,
    subreg_info,
)
from dragonslayer.analysis.symbolic_execution.executor import SymbolicExecutor
from dragonslayer.analysis.symbolic_execution.lifter import LiftedInstruction
from dragonslayer.analysis.pattern_analysis.recognizer import PatternRecognizer
from dragonslayer.ml.classifier import VMClassifier, FeatureExplainer
from dragonslayer.ml.model import VMHandlerModel, HANDLER_CATEGORIES
from dragonslayer.ml.trainer import ModelTrainer, prepare_training_data
from dragonslayer.ml.pipeline import extract_handler_features


def _has_sklearn() -> bool:
    try:
        import sklearn  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# 1. ByteTaintMap — SIMD register sizes
# ---------------------------------------------------------------------------


class TestByteTaintMapSIMD:
    """Verify ByteTaintMap allocates correct sizes for SIMD registers."""

    def test_gp_register_is_8_bytes(self):
        m = ByteTaintMap()
        arr = m._ensure("rax")
        assert len(arr) == 8

    def test_zmm_register_is_64_bytes(self):
        m = ByteTaintMap()
        arr = m._ensure("zmm0")
        assert len(arr) == 64

    def test_xmm_taint_covers_16_bytes(self):
        """Tainting xmm0 should set 16 bytes (bits 0-127) in zmm0's array."""
        m = ByteTaintMap()
        m.set_bytes("xmm0", TaintTag.INPUT)
        arr = m._map["zmm0"]
        # First 16 bytes should be INPUT
        for i in range(16):
            assert arr[i] == TaintTag.INPUT, f"byte {i} not INPUT"
        # Remaining bytes should be CLEAN
        for i in range(16, 64):
            assert arr[i] == TaintTag.CLEAN, f"byte {i} not CLEAN"

    def test_ymm_taint_covers_32_bytes(self):
        """Tainting ymm0 should set 32 bytes in zmm0's array."""
        m = ByteTaintMap()
        m.set_bytes("ymm0", TaintTag.VM_OPERAND)
        arr = m._map["zmm0"]
        for i in range(32):
            assert arr[i] == TaintTag.VM_OPERAND
        for i in range(32, 64):
            assert arr[i] == TaintTag.CLEAN

    def test_zmm_taint_covers_64_bytes(self):
        """Tainting zmm0 should set all 64 bytes."""
        m = ByteTaintMap()
        m.set_bytes("zmm0", TaintTag.CRYPTO)
        arr = m._map["zmm0"]
        assert all(b == TaintTag.CRYPTO for b in arr)
        assert len(arr) == 64

    def test_xmm_get_bytes_reads_16(self):
        """get_bytes('xmm0') should OR first 16 bytes."""
        m = ByteTaintMap()
        m.set_bytes("xmm0", TaintTag.INPUT)
        tag = m.get_bytes("xmm0")
        assert tag & TaintTag.INPUT

    def test_simd_interprocedural_context(self):
        """push/pop_call_context preserves SIMD byte taint."""
        t = TaintTracker(sub_register_aware=True)
        t.taint_register("xmm0", TaintTag.INPUT)
        assert t._byte_taint.get_bytes("xmm0") & TaintTag.INPUT

        t.push_call_context()
        t.taint_register("xmm0", TaintTag.COMPUTED)
        t.pop_call_context(return_regs=())

        # Restored: xmm0 should have INPUT, not COMPUTED
        tag = t._byte_taint.get_bytes("xmm0")
        assert tag & TaintTag.INPUT
        assert not (tag & TaintTag.COMPUTED)


# ---------------------------------------------------------------------------
# 2. ML training pipeline — train, evaluate, classify known categories
# ---------------------------------------------------------------------------


def _make_handler(category: str, *, count: int = 5) -> dict:
    """Create a synthetic handler dict for a given category.

    Uses operation names matching _OP_TO_LABEL keys in trainer.py.
    """
    _CATEGORY_SPEC: dict[str, tuple[str, list[dict]]] = {
        "arithmetic": ("vm_add", [
            {"mnemonic": "add", "operands": "eax, ebx"},
            {"mnemonic": "sub", "operands": "ecx, edx"},
            {"mnemonic": "imul", "operands": "eax, ecx"},
            {"mnemonic": "inc", "operands": "eax"},
            {"mnemonic": "dec", "operands": "ecx"},
        ]),
        "bitwise": ("vm_xor", [
            {"mnemonic": "xor", "operands": "eax, ebx"},
            {"mnemonic": "and", "operands": "ecx, edx"},
            {"mnemonic": "or", "operands": "eax, ecx"},
            {"mnemonic": "shl", "operands": "eax, 2"},
            {"mnemonic": "shr", "operands": "ecx, 1"},
        ]),
        "stack": ("vm_push", [
            {"mnemonic": "push", "operands": "rbp"},
            {"mnemonic": "push", "operands": "rax"},
            {"mnemonic": "pop", "operands": "rbx"},
        ]),
        "nop": ("vm_nop", [
            {"mnemonic": "nop", "operands": ""},
            {"mnemonic": "nop", "operands": ""},
            {"mnemonic": "nop", "operands": ""},
        ]),
        "control_flow": ("vm_jmp", [
            {"mnemonic": "jmp", "operands": "0x1000"},
            {"mnemonic": "je", "operands": "0x2000"},
            {"mnemonic": "call", "operands": "0x3000"},
        ]),
    }
    op_name, insns = _CATEGORY_SPEC.get(
        category,
        ("vm_unknown", [{"mnemonic": "mov", "operands": "eax, [rbx]"}]),
    )
    return {
        "instructions": insns[:count],
        "operation": op_name,
    }


class TestMLTrainingPipeline:
    """Test that the ML pipeline can train, evaluate, and classify."""

    def test_prepare_training_data(self):
        """prepare_training_data extracts features and labels."""
        handlers = [_make_handler("arithmetic"), _make_handler("bitwise")]
        features, labels = prepare_training_data(handlers)
        assert len(features) == 2
        assert len(labels) == 2
        assert labels[0] == "arithmetic"
        assert labels[1] == "bitwise"

    def test_heuristic_training(self):
        """ModelTrainer.train works without sklearn (heuristic validation)."""
        handlers = [_make_handler(cat) for cat in ("arithmetic", "bitwise", "nop")]
        features, labels = prepare_training_data(handlers)
        trainer = ModelTrainer()
        result = trainer.train(features, labels)
        assert result.accuracy >= 0.0

    @pytest.mark.skipif(
        not _has_sklearn(), reason="scikit-learn not installed"
    )
    def test_sklearn_training_and_classify(self):
        """Full cycle: train sklearn model, classify known samples."""
        # Build dataset: 10 of each category
        categories = ["arithmetic", "bitwise", "stack", "nop"]
        handlers = []
        for cat in categories:
            for _ in range(10):
                handlers.append(_make_handler(cat))

        features, labels = prepare_training_data(handlers)
        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        result = trainer.train(features, labels, n_estimators=20)

        # Should have trained with sklearn
        assert model.is_trained
        assert result.accuracy > 0.0

        # Classify a known arithmetic handler
        clf = VMClassifier(model=model)
        pred = clf.classify(_make_handler("arithmetic"))
        assert pred.label in HANDLER_CATEGORIES
        assert pred.confidence > 0.0
        assert pred.metadata.get("method") == "sklearn"

    def test_evaluate_returns_accuracy(self):
        """Evaluate method returns an accuracy dict."""
        handlers = [_make_handler(cat) for cat in ("arithmetic", "bitwise", "nop")]
        features, labels = prepare_training_data(handlers)
        trainer = ModelTrainer()
        metrics = trainer.evaluate(features, labels)
        assert "accuracy" in metrics
        assert "total" in metrics

    def test_classify_batch_tolerates_errors(self):
        """classify_batch returns results for all items even if some fail."""
        clf = VMClassifier()
        handlers = [
            _make_handler("arithmetic"),
            {},  # empty → should gracefully produce unknown
            _make_handler("nop"),
        ]
        results = clf.classify_batch(handlers)
        assert len(results) == 3


# ---------------------------------------------------------------------------
# 3. Reversed scale*index in _eval_addr_expr
# ---------------------------------------------------------------------------


class TestEvalAddrExprReversed:
    """Verify _eval_addr_expr handles both reg*scale and scale*reg."""

    def test_register_times_scale(self):
        """Standard form: rcx*8."""
        result = SymbolicExecutor._eval_addr_expr("rcx*8", {"rcx": 0x10})
        assert result == 0x80

    def test_scale_times_register(self):
        """Reversed form: 8*rcx."""
        result = SymbolicExecutor._eval_addr_expr("8*rcx", {"rcx": 0x10})
        assert result == 0x80

    def test_full_sib_reversed(self):
        """rax+4*rdx+0x100 (reversed scale*index)."""
        result = SymbolicExecutor._eval_addr_expr(
            "rax+4*rdx+0x100", {"rax": 0x1000, "rdx": 0x10}
        )
        assert result == 0x1000 + 4 * 0x10 + 0x100

    def test_indirect_with_reversed_scale(self):
        """Full _resolve_indirect_targets with reversed scale pattern."""
        insn = LiftedInstruction(
            address=0x5000,
            size=3,
            mnemonic="jmp",
            operands="qword ptr [rax+4*rcx]",
            category="branch_unconditional",
            raw_bytes=b"\xff\x24\x88",
            registers={"rax": 0x2000, "rcx": 0x100},
        )
        block_addrs = {0x2400}  # 0x2000 + 4*0x100 = 0x2400
        targets = SymbolicExecutor._resolve_indirect_targets(insn, block_addrs)
        assert 0x2400 in targets


# ---------------------------------------------------------------------------
# 4. NOP stripping — second pass after OPCODE_EQUIV
# ---------------------------------------------------------------------------


class TestNOPStrippingOrder:
    """Verify opcode-equiv → NOP sequence gets fully cleaned."""

    def test_sub_eax_zero_fully_stripped(self):
        """83E800 → 90 → stripped. Only 'C3' should remain."""
        result = PatternRecognizer.normalize_semantics("83E800C3")
        # 83E800 → 90 (by _OPCODE_EQUIV), then 90 stripped by second NOP pass
        assert result == "C3"

    def test_mov_eax_eax_fully_stripped(self):
        """89C0 → 90 → stripped."""
        result = PatternRecognizer.normalize_semantics("89C0C3")
        assert result == "C3"

    def test_double_nop_equiv_stripped(self):
        """Two opcode-equiv NOPs in sequence both get stripped."""
        result = PatternRecognizer.normalize_semantics("83E80089C0C3")
        # 83E800→90, 89C0→90, then both 90s stripped
        assert result == "C3"

    def test_original_nops_also_stripped(self):
        """Both original and opcode-equiv NOPs stripped in one pass."""
        result = PatternRecognizer.normalize_semantics("9083E800C3")
        assert result == "C3"


# ---------------------------------------------------------------------------
# 5. model save/load round-trip
# ---------------------------------------------------------------------------


class TestModelSaveLoad:
    """Test model serialisation round-trip."""

    def test_is_trained_property(self):
        model = VMHandlerModel()
        assert not model.is_trained

    def test_save_without_model_raises(self):
        model = VMHandlerModel()
        with pytest.raises(RuntimeError, match="No trained model"):
            model.save("/tmp/test_model.pkl")

    @pytest.mark.skipif(not _has_sklearn(), reason="scikit-learn not installed")
    def test_save_load_roundtrip(self, tmp_path):
        """Train, save, load, verify predictions match."""
        categories = ["arithmetic", "bitwise", "nop"]
        handlers = []
        for cat in categories:
            for _ in range(10):
                handlers.append(_make_handler(cat))

        features, labels = prepare_training_data(handlers)
        model = VMHandlerModel()
        trainer = ModelTrainer(model)
        trainer.train(features, labels, n_estimators=10)

        path = str(tmp_path / "model.joblib")
        model.save(path, feature_names=features[0].feature_names)

        # Load into a fresh model
        model2 = VMHandlerModel()
        model2.load(path)
        assert model2.is_trained

        # Predictions should match
        for h in handlers[:3]:
            fv = extract_handler_features(h)
            p1 = model.predict({"values": fv.values, "names": fv.feature_names})
            p2 = model2.predict({"values": fv.values, "names": fv.feature_names})
            assert p1.label == p2.label
