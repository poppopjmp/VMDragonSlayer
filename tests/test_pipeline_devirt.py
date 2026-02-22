"""Tests for pipeline _run_stage helper and devirtualize stage."""

import pytest
from unittest.mock import MagicMock

from dragonslayer.core.pipeline import (
    AnalysisPipeline,
    PipelineConfig,
    StageResult,
    create_full_pipeline,
    create_vmprotect_devirt_pipeline,
    create_quick_scan_pipeline,
)


# ---------------------------------------------------------------------------
# _run_stage helper
# ---------------------------------------------------------------------------

class TestRunStage:
    def setup_method(self):
        self.pipe = AnalysisPipeline(config=MagicMock(_config={}))

    def test_success_returns_data(self):
        result = self.pipe._run_stage("test_stage", lambda: {"foo": 42})
        assert isinstance(result, StageResult)
        assert result.success is True
        assert result.stage == "test_stage"
        assert result.data["foo"] == 42
        assert result.duration > 0

    def test_exception_returns_failure(self):
        """Framework exceptions are caught; programming errors propagate."""
        from dragonslayer.core.exceptions import AnalysisError

        def _boom():
            raise AnalysisError("kaboom")

        result = self.pipe._run_stage("test_stage", _boom)
        assert result.success is False
        assert "kaboom" in result.error
        assert result.stage == "test_stage"

    def test_stores_in_ctx(self):
        ctx = MagicMock()
        ctx.shared_data = {}
        self.pipe._run_stage("my_stage", lambda: {"val": 1}, ctx=ctx)
        assert ctx.shared_data["my_stage"] == {"val": 1}

    def test_passthrough_stage_result(self):
        """If fn returns a StageResult directly, pass it through."""
        sr = StageResult(stage="custom", success=True, data={"x": 1})
        result = self.pipe._run_stage("ignored_name", lambda: sr)
        assert result.stage == "custom"
        assert result.data == {"x": 1}

    def test_non_dict_return(self):
        result = self.pipe._run_stage("test_stage", lambda: "not a dict")
        assert result.success is True
        assert result.data == {}


# ---------------------------------------------------------------------------
# devirtualize stage
# ---------------------------------------------------------------------------

class TestDevirtualizeStage:
    def setup_method(self):
        self.pipe = AnalysisPipeline(config=MagicMock(_config={}))

    def test_skipped_when_no_trace(self):
        """Without dynamic analysis data, devirtualize should skip."""
        ctx = MagicMock()
        ctx.shared_data = {}
        result = self.pipe._run_devirtualize(b"\x00" * 16, ctx)
        assert result.success is True
        assert result.data.get("skipped") is True

    def test_skipped_when_empty_shared_data(self):
        ctx = MagicMock()
        ctx.shared_data = {"dynamic": {}}
        result = self.pipe._run_devirtualize(b"\x00" * 16, ctx)
        assert result.success is True
        assert result.data.get("skipped") is True


# ---------------------------------------------------------------------------
# Pipeline profiles include devirtualize
# ---------------------------------------------------------------------------

class TestPipelineProfiles:
    def test_full_pipeline_includes_devirt(self):
        _, cfg = create_full_pipeline(config=MagicMock(_config={}))
        assert "devirtualize" in cfg.stages

    def test_vmprotect_pipeline_includes_devirt(self):
        _, cfg = create_vmprotect_devirt_pipeline(config=MagicMock(_config={}))
        assert "devirtualize" in cfg.stages
        # Should come after dispatcher_analysis
        idx_disp = cfg.stages.index("dispatcher_analysis")
        idx_devirt = cfg.stages.index("devirtualize")
        assert idx_devirt > idx_disp

    def test_quick_scan_excludes_devirt(self):
        _, cfg = create_quick_scan_pipeline(config=MagicMock(_config={}))
        assert "devirtualize" not in cfg.stages
