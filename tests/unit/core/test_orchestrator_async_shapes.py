import asyncio

import pytest
from dragonslayer.core.orchestrator import Orchestrator, AnalysisRequest, AnalysisType


@pytest.mark.asyncio
async def test_async_paths_return_shapes():
    orch = Orchestrator()
    req_bytes = b"\x90" * 64
    res = await orch.execute_analysis(
        AnalysisRequest(binary_data=req_bytes, analysis_type=AnalysisType.VM_DISCOVERY)
    )
    assert isinstance(res.results, dict)
