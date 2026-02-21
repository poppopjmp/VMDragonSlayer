"""
B97 — Handler semantics TypedDicts, ML docstrings, GZipMiddleware.

Tests:
  1. Handler semantics TypedDict shapes + to_dict() key validation
  2. ML model/ensemble docstring completeness
  3. GZipMiddleware presence
  4. CORS headers on responses
"""

from __future__ import annotations

import inspect
from typing import Any, Dict

import pytest


# ---------------------------------------------------------------------------
# 1. Handler semantics TypedDicts
# ---------------------------------------------------------------------------


class TestHandlerSemanticsTypedDicts:
    """Validate TypedDicts for handler_semantics to_dict() returns."""

    def test_handler_semantic_dict_importable(self) -> None:
        from dragonslayer.analysis.handler_semantics import HandlerSemanticDict
        assert HandlerSemanticDict is not None

    def test_opcode_table_entry_dict_importable(self) -> None:
        from dragonslayer.analysis.handler_semantics import OpcodeTableEntryDict
        assert OpcodeTableEntryDict is not None

    def test_semantic_opcode_table_dict_importable(self) -> None:
        from dragonslayer.analysis.handler_semantics import SemanticOpcodeTableDict
        assert SemanticOpcodeTableDict is not None

    def test_handler_semantic_to_dict_keys(self) -> None:
        from dragonslayer.analysis.handler_semantics import (
            HandlerSemantic,
            HandlerSemanticDict,
        )
        hs = HandlerSemantic(handler_address=0x1000, operation="vm_add", confidence=0.9)
        d = hs.to_dict()
        expected = set(HandlerSemanticDict.__annotations__)
        assert set(d.keys()) == expected

    def test_handler_semantic_to_dict_values(self) -> None:
        from dragonslayer.analysis.handler_semantics import HandlerSemantic
        hs = HandlerSemantic(
            handler_address=0xCAFE,
            operation="vm_xor",
            confidence=0.85,
            operand_count=2,
            reads_memory=True,
        )
        d = hs.to_dict()
        assert d["handler_address"] == hex(0xCAFE)
        assert d["operation"] == "vm_xor"
        assert d["reads_memory"] is True

    def test_opcode_table_entry_to_dict_keys(self) -> None:
        from dragonslayer.analysis.handler_semantics import (
            HandlerSemantic,
            OpcodeTableEntry,
            OpcodeTableEntryDict,
        )
        sem = HandlerSemantic(handler_address=0x100, operation="vm_add")
        entry = OpcodeTableEntry(opcode=0x10, handler_address=0x100, semantic=sem)
        d = entry.to_dict()
        expected = set(OpcodeTableEntryDict.__annotations__)
        assert set(d.keys()) == expected

    def test_semantic_opcode_table_to_dict_keys(self) -> None:
        from dragonslayer.analysis.handler_semantics import (
            SemanticOpcodeTable,
            SemanticOpcodeTableDict,
        )
        table = SemanticOpcodeTable(handler_count=0, unique_operations=0)
        d = table.to_dict()
        expected = set(SemanticOpcodeTableDict.__annotations__)
        assert set(d.keys()) == expected

    def test_semantic_opcode_table_nesting(self) -> None:
        from dragonslayer.analysis.handler_semantics import (
            HandlerSemantic,
            OpcodeTableEntry,
            SemanticOpcodeTable,
        )
        sem = HandlerSemantic(handler_address=0x200, operation="vm_sub", confidence=0.7)
        entry = OpcodeTableEntry(opcode=0x20, handler_address=0x200, semantic=sem)
        table = SemanticOpcodeTable(
            entries=[entry], handler_count=1, unique_operations=1
        )
        d = table.to_dict()
        assert len(d["entries"]) == 1
        assert d["entries"][0]["operation"] == "vm_sub"


# ---------------------------------------------------------------------------
# 2. Handler semantics dataclass Attributes docstrings
# ---------------------------------------------------------------------------


class TestHandlerSemanticsDocstrings:
    """Verify handler_semantics dataclass docstrings have Attributes."""

    @pytest.mark.parametrize(
        "cls_name",
        ["HandlerSemantic", "OpcodeTableEntry", "SemanticOpcodeTable"],
    )
    def test_has_attributes_section(self, cls_name: str) -> None:
        import dragonslayer.analysis.handler_semantics as mod
        cls = getattr(mod, cls_name)
        doc = cls.__doc__ or ""
        assert "Attributes:" in doc, f"{cls_name} missing Attributes section"


# ---------------------------------------------------------------------------
# 3. ML module docstring completeness
# ---------------------------------------------------------------------------


class TestMLModelDocstrings:
    """model.py methods should have Args/Returns/Raises."""

    _METHODS = [
        ("predict", "BaseModel"),
        ("predict_batch", "BaseModel"),
    ]

    @pytest.mark.parametrize("method_name,cls_name", _METHODS)
    def test_model_docstring_has_body(self, method_name: str, cls_name: str) -> None:
        import dragonslayer.ml.model as mod
        cls = getattr(mod, cls_name)
        fn = getattr(cls, method_name)
        doc = fn.__doc__ or ""
        assert "Args:" in doc or "Returns:" in doc or "Raises:" in doc, (
            f"{cls_name}.{method_name} still has skeleton docstring"
        )

    def test_score_rules_docstring(self) -> None:
        from dragonslayer.ml.model import _score_rules
        doc = _score_rules.__doc__ or ""
        assert "Args:" in doc and "Returns:" in doc

    def test_is_trained_docstring(self) -> None:
        from dragonslayer.ml.model import VMHandlerModel
        doc = VMHandlerModel.is_trained.fget.__doc__ or ""
        assert "Returns:" in doc


class TestMLEnsembleDocstrings:
    """ensemble.py methods should have Args/Returns."""

    _METHODS = ["predict", "_aggregate"]

    @pytest.mark.parametrize("method_name", _METHODS)
    def test_ensemble_docstring(self, method_name: str) -> None:
        from dragonslayer.ml.ensemble import EnsembleClassifier
        fn = getattr(EnsembleClassifier, method_name)
        doc = fn.__doc__ or ""
        assert "Args:" in doc or "Returns:" in doc, (
            f"EnsembleClassifier.{method_name} still has skeleton docstring"
        )

    def test_build_meta_features_docstring(self) -> None:
        from dragonslayer.ml.ensemble import StackedEnsemble
        doc = StackedEnsemble._build_meta_features.__doc__ or ""
        assert "Args:" in doc and "Returns:" in doc


# ---------------------------------------------------------------------------
# 4. GZipMiddleware + CORS
# ---------------------------------------------------------------------------


class TestGZipMiddleware:
    """Verify GZipMiddleware is registered on the app."""

    def test_gzip_middleware_present(self) -> None:
        from dragonslayer.api.server import app
        middleware_classes = [
            type(m).__name__
            for m in getattr(app, "user_middleware", [])
        ]
        # FastAPI stores middleware specs as Middleware objects with cls attr
        middleware_cls_names = []
        for mw in getattr(app, "user_middleware", []):
            middleware_cls_names.append(mw.cls.__name__)
        assert "GZipMiddleware" in middleware_cls_names

    @pytest.mark.anyio
    async def test_gzip_import_available(self) -> None:
        """GZipMiddleware should be importable from starlette."""
        from starlette.middleware.gzip import GZipMiddleware
        assert GZipMiddleware is not None

    @pytest.mark.anyio
    async def test_cors_headers_present(self) -> None:
        """OPTIONS preflight should return CORS headers."""
        import httpx
        from dragonslayer.api.server import app
        transport = httpx.ASGITransport(app=app)  # type: ignore[arg-type]
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            resp = await c.options(
                "/health",
                headers={
                    "Origin": "http://example.com",
                    "Access-Control-Request-Method": "GET",
                },
            )
        # CORS should respond with allow-origin header
        assert "access-control-allow-origin" in resp.headers
