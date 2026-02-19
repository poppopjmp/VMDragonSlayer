"""
VMDragonSlayer Core API Facade

Re-exports :class:`VMDragonSlayerAPI` so that
``from ..core.api import VMDragonSlayerAPI`` works in the server module.
"""

from .orchestrator import VMDragonSlayerAPI

__all__ = ["VMDragonSlayerAPI"]
