"""
ML Feature Pipeline
====================

Feature extraction and vector construction for the ML classification
pipeline.  :class:`FeatureExtractor` converts raw binary analysis
artefacts (disassembly, CFG stats, taint data) into numeric feature
vectors consumed by :class:`~dragonslayer.ml.model.BaseModel`.

These are **interface stubs** — concrete implementations require
domain-specific feature engineering to be filled in.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

import logging

logger = logging.getLogger(__name__)


@dataclass
class FeatureVector:
    """Numeric feature vector with metadata."""

    values: List[float] = field(default_factory=list)
    feature_names: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def dimension(self) -> int:
        return len(self.values)


class FeatureExtractor:
    """Convert analysis artefacts into :class:`FeatureVector` instances.

    Subclass or configure with a *feature_spec* dict that maps analysis
    keys to extraction callables.
    """

    def __init__(self, feature_spec: Dict[str, Any] | None = None) -> None:
        self._spec = feature_spec or {}

    def extract(self, analysis_data: Dict[str, Any]) -> FeatureVector:
        """Build a feature vector from *analysis_data*.

        Raises :exc:`NotImplementedError` until a concrete feature spec
        is supplied.
        """
        if not self._spec:
            raise NotImplementedError(
                "FeatureExtractor requires a feature_spec mapping to "
                "convert analysis data into numeric features"
            )
        values: List[float] = []
        names: List[str] = []
        for key, extractor_fn in self._spec.items():
            val = extractor_fn(analysis_data)
            if isinstance(val, (list, tuple)):
                values.extend(float(v) for v in val)
                names.extend(f"{key}_{i}" for i in range(len(val)))
            else:
                values.append(float(val))
                names.append(key)
        return FeatureVector(values=values, feature_names=names)
