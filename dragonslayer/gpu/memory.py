"""
GPU Memory Manager
==================

Tracks GPU memory allocations, enforces quotas, and provides a
simple arena allocator for analysis kernels.

Stub — requires a GPU backend for real memory management.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


class GPUMemoryManager:
    """Track and limit GPU memory usage.

    All methods raise :exc:`NotImplementedError` until a GPU backend
    is available.
    """

    def __init__(self, max_bytes: int = 2 * 1024 ** 3) -> None:
        self.max_bytes = max_bytes
        self._allocated = 0

    def allocate(self, size: int) -> Any:
        """Allocate *size* bytes on the GPU and return a handle.

        Args:
            size: Number of bytes to allocate.

        Returns:
            An opaque handle to the allocated GPU buffer.

        Raises:
            NotImplementedError: Always — no GPU backend is installed.
        """
        raise NotImplementedError("GPU memory allocation not implemented")

    def free(self, handle: Any) -> None:
        """Release a previously allocated GPU buffer.

        Args:
            handle: Handle returned by :meth:`allocate`.

        Raises:
            NotImplementedError: Always — no GPU backend is installed.
        """
        raise NotImplementedError("GPU memory free not implemented")

    @property
    def used_bytes(self) -> int:
        return self._allocated

    @property
    def free_bytes(self) -> int:
        return max(0, self.max_bytes - self._allocated)

    def stats(self) -> Dict[str, Any]:
        """Return memory usage statistics.

        Returns:
            Dict with ``max_bytes``, ``allocated_bytes``, and
            ``free_bytes`` keys.
        """
        return {
            "max_bytes": self.max_bytes,
            "allocated_bytes": self._allocated,
            "free_bytes": self.free_bytes,
        }
