"""
GPU Compute Engine
==================

Central dispatch for GPU-accelerated analysis tasks.

Stub — concrete implementation requires a CUDA / OpenCL backend.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class GPUEngine:
    """Manage GPU device selection and kernel dispatch.

    Raises :exc:`NotImplementedError` for all compute methods until a
    GPU backend (CuPy, PyCUDA, PyOpenCL) is installed and configured.
    """

    def __init__(self, device_id: int = 0) -> None:
        self.device_id = device_id
        self._initialised = False

    def initialise(self) -> None:
        """Initialise the GPU device context."""
        raise NotImplementedError(
            "GPUEngine requires a CUDA/OpenCL backend — "
            "install cupy or pycuda to enable GPU acceleration"
        )

    def pattern_match_bulk(
        self,
        data: bytes,
        patterns: List[bytes],
    ) -> List[Dict[str, Any]]:
        """Run parallel pattern matching on the GPU."""
        raise NotImplementedError("GPU pattern matching not implemented")

    def symbolic_evaluate_batch(
        self,
        expressions: List[Any],
    ) -> List[Any]:
        """Batch-evaluate symbolic expressions on the GPU."""
        raise NotImplementedError("GPU symbolic evaluation not implemented")

    def shutdown(self) -> None:
        """Release GPU resources."""
        self._initialised = False
