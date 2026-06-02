"""VMDragonSlayer — Advanced VM detection and analysis framework.

This is the top-level package marker. It is intentionally lightweight: it only
exposes package metadata so that importing :mod:`dragonslayer` has no heavy
side effects. Submodules (``dragonslayer.core``, ``dragonslayer.analysis`` …)
are imported explicitly by callers.
"""

__version__ = "0.9.1"

__all__ = ["__version__"]
