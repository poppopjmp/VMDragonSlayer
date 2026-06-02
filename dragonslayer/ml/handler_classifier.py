"""
Handler Classification Bridge
==============================

Connects the :mod:`~dragonslayer.ml` pipeline to the devirtualisation
analysis path.  Provides:

* :class:`HandlerFeatureExtractor` — feature-spec–backed extractor for
  :class:`~..vm_discovery.handler_boundaries.HandlerBoundary` records.
* :class:`TrainedHandlerModel` — scikit-learn–backed
  :class:`~..ml.model.VMHandlerModel` with heuristic fallback when no
  trained model is available.
* :func:`classify_handlers` — convenience function that classifies a
  list of handler boundaries.

Usage::

    from dragonslayer.ml.handler_classifier import classify_handlers

    results = classify_handlers(boundaries)
    for boundary, prediction in zip(boundaries, results):
        print(f"vIP={boundary.vip_value:#x}  → {prediction.label} "
              f"({prediction.confidence:.0%})")
"""

from __future__ import annotations

import json
import logging
import math
from collections.abc import Sequence
from typing import Any

from dragonslayer.analysis.vm_discovery.handler_boundaries import (
    HandlerBoundary,
)
from dragonslayer.ml.classifier import VMClassifier
from dragonslayer.ml.model import PredictionResult, VMHandlerModel
from dragonslayer.ml.pipeline import FeatureExtractor
from dragonslayer.ml.taxonomy import CANONICAL_CATEGORIES
from dragonslayer.ml.taxonomy import canonicalize as _canonicalize

logger = logging.getLogger(__name__)

try:
    from sklearn.ensemble import RandomForestClassifier as _RFC
    SKLEARN_AVAILABLE = True
except ImportError:
    _RFC = None  # type: ignore[assignment, misc]
    SKLEARN_AVAILABLE = False


# ---------------------------------------------------------------------------
# Feature specification
# ---------------------------------------------------------------------------

# Handler categories we classify into  (canonical taxonomy).
HANDLER_CATEGORIES = list(CANONICAL_CATEGORIES)

def _safe_int(v: Any) -> int:
    """Parse an int that may be hex string or int."""
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        return int(v, 0)
    return int(v)


def _handler_feature_spec() -> dict[str, Any]:
    """Build the feature spec dict for FeatureExtractor."""

    return {
        "instruction_count": lambda d: float(d.get("instruction_count", 0)),
        "vip_delta": lambda d: float(d.get("vip_delta", 0)),
        "abs_vip_delta": lambda d: float(abs(d.get("vip_delta", 0))),
        "handler_span": lambda d: float(
            d.get("trace_end", 0) - d.get("trace_start", 0)
        ),
        "insn_density": lambda d: (
            float(d.get("instruction_count", 0))
            / max(float(d.get("trace_end", 1) - d.get("trace_start", 0)), 1)
        ),
        "log_handler_addr": lambda d: (
            math.log2(max(_safe_int(d.get("handler_address", 1)), 1))
        ),
    }


# ---------------------------------------------------------------------------
# Heuristic model (no training needed)
# ---------------------------------------------------------------------------

# B87: Default heuristic thresholds — can be overridden via JSON config.
_DEFAULT_HEURISTIC_CONFIG: dict[str, Any] = {
    "rules": [
        {"label": "nop",          "confidence": 0.70, "max_insn": 3},
        {"label": "control_flow", "confidence": 0.50, "abs_delta_eq": 0},
        {"label": "arithmetic",   "confidence": 0.60, "max_abs_delta": 2, "max_insn": 8},
        {"label": "comparison",   "confidence": 0.50, "max_abs_delta": 2, "min_insn": 9},
        {"label": "memory",       "confidence": 0.55, "min_abs_delta": 3, "max_abs_delta": 5, "max_insn": 12},
        {"label": "control_flow", "confidence": 0.50, "min_abs_delta": 6, "min_insn": 16},
        {"label": "bitwise",      "confidence": 0.45, "min_density": 0.8},
        {"label": "system",       "confidence": 0.40, "min_insn": 21},
    ],
    "default_label": "unknown",
    "default_confidence": 0.30,
}


class TrainedHandlerModel(VMHandlerModel):
    """VM handler model with scikit-learn backend and heuristic fallback.

    When :meth:`load` succeeds (a pickled sklearn model exists), all
    predictions go through the forest.  Otherwise a rule-based heuristic
    provides reasonable default classifications.
    """

    name: str = "vm_handler_trained"

    def __init__(self) -> None:
        super().__init__()
        self._sklearn_model: Any | None = None
        self._label_names: list[str] = HANDLER_CATEGORIES
        self._heuristic_config: dict[str, Any] = dict(_DEFAULT_HEURISTIC_CONFIG)

    # ---- heuristic config -----------------------------------------------

    def configure_heuristics(self, config: dict[str, Any]) -> None:
        """Override heuristic thresholds with a custom config dict.

        The *config* dictionary should match the structure of
        ``_DEFAULT_HEURISTIC_CONFIG`` (see module-level definition).
        """
        if "rules" in config:
            self._heuristic_config["rules"] = config["rules"]
        if "default_label" in config:
            self._heuristic_config["default_label"] = config["default_label"]
        if "default_confidence" in config:
            self._heuristic_config["default_confidence"] = config["default_confidence"]

    @classmethod
    def load_heuristic_config(cls, path: str) -> dict[str, Any]:
        """Load heuristic config from a JSON file.

        Returns the parsed dict (also usable with :meth:`configure_heuristics`).
        Raises ``FileNotFoundError`` or ``json.JSONDecodeError`` on failure.
        """
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    # ---- load -----------------------------------------------------------

    def load(self, path: str) -> None:
        """Load a pickled scikit-learn model from *path*.

        Silently falls back to heuristic mode if loading fails.
        """
        if not SKLEARN_AVAILABLE:
            logger.info("scikit-learn not available; using heuristic model")
            return
        try:
            import pickle
            from pathlib import Path

            p = Path(path)
            if not p.exists():
                logger.info("Model file %s not found; using heuristic mode", path)
                return
            with open(p, "rb") as fh:
                obj = pickle.load(fh)  # noqa: S301  # nosec B301 — trusted local model artifact only
            if hasattr(obj, "predict_proba"):
                self._sklearn_model = obj
                logger.info("Loaded sklearn model from %s", path)
            else:
                logger.warning("Loaded object has no predict_proba; heuristic mode")
        except (OSError, ValueError, TypeError, pickle.UnpicklingError, EOFError) as exc:
            logger.warning("Failed to load model from %s: %s", path, exc)

    # ---- predict --------------------------------------------------------

    def predict(self, features: dict[str, Any]) -> PredictionResult:
        """Classify one handler from its feature vector."""
        values = features.get("values", [])
        names = features.get("names", [])

        if self._sklearn_model is not None:
            return self._predict_sklearn(values, names)
        return self._predict_heuristic(values, names)

    def _predict_sklearn(
        self, values: list[float], names: list[str],
    ) -> PredictionResult:
        """Prediction via trained sklearn model."""
        import numpy as np

        X = np.array(values).reshape(1, -1)
        proba = self._sklearn_model.predict_proba(X)[0]
        classes = list(self._sklearn_model.classes_)
        best_idx = int(proba.argmax())
        label = str(classes[best_idx])
        conf = float(proba[best_idx])
        prob_dict = {str(c): float(p) for c, p in zip(classes, proba, strict=False)}
        return PredictionResult(
            label=_canonicalize(label),
            confidence=conf,
            probabilities=prob_dict,
            metadata={"method": "sklearn", "feature_names": names},
        )

    def _predict_heuristic(
        self, values: list[float], names: list[str],
    ) -> PredictionResult:
        """Rule-based classification when no trained model is available.

        B87: Thresholds are now driven by ``self._heuristic_config`` which
        can be overridden via :meth:`configure_heuristics` or loaded from
        a JSON file.
        """
        feat = dict(zip(names, values, strict=False))

        insn_count = feat.get("instruction_count", 0)
        vip_delta = feat.get("vip_delta", 0)
        abs_delta = feat.get("abs_vip_delta", abs(vip_delta))
        density = feat.get("insn_density", 0)

        cfg = self._heuristic_config
        label = cfg.get("default_label", "unknown")
        conf = cfg.get("default_confidence", 0.30)

        for rule in cfg.get("rules", []):
            # Each rule is a dict with threshold keys.  A rule matches if
            # ALL specified thresholds are satisfied.
            matched = True
            if "max_insn" in rule and insn_count > rule["max_insn"]:
                matched = False
            if "min_insn" in rule and insn_count < rule["min_insn"]:
                matched = False
            if "abs_delta_eq" in rule and abs_delta != rule["abs_delta_eq"]:
                matched = False
            if "max_abs_delta" in rule and abs_delta > rule["max_abs_delta"]:
                matched = False
            if "min_abs_delta" in rule and abs_delta < rule["min_abs_delta"]:
                matched = False
            if "min_density" in rule and density < rule["min_density"]:
                matched = False
            if matched:
                label = rule["label"]
                conf = rule["confidence"]
                break

        # Build probability distribution centred on the chosen label.
        probs = dict.fromkeys(HANDLER_CATEGORIES, 0.0)
        probs[label] = conf
        remaining = 1.0 - conf
        others = [c for c in HANDLER_CATEGORIES if c != label]
        if others:
            share = remaining / len(others)
            for c in others:
                probs[c] = round(share, 4)

        return PredictionResult(
            label=label,
            confidence=conf,
            probabilities=probs,
            metadata={"method": "heuristic", "feature_names": names},
        )


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def build_handler_classifier(
    model_path: str | None = None,
    heuristic_config_path: str | None = None,
) -> VMClassifier:
    """Create a ready-to-use classifier for handler boundaries.

    Args:
        model_path: Optional path to a trained sklearn model pickle.
            If ``None`` or not found, falls back to heuristic mode.
        heuristic_config_path: Optional path to a JSON file with
            heuristic threshold overrides (B87).

    Returns:
        A :class:`VMClassifier` configured for handler classification.
    """
    extractor = FeatureExtractor(feature_spec=_handler_feature_spec())
    model = TrainedHandlerModel()
    if heuristic_config_path:
        try:
            cfg = TrainedHandlerModel.load_heuristic_config(heuristic_config_path)
            model.configure_heuristics(cfg)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load heuristic config from %s: %s", heuristic_config_path, exc)
    if model_path:
        model.load(model_path)
    return VMClassifier(model=model, extractor=extractor)


def classify_handlers(
    boundaries: Sequence[HandlerBoundary],
    *,
    model_path: str | None = None,
) -> list[PredictionResult]:
    """Classify a list of handler boundaries.

    Convenience wrapper that builds a classifier and runs it on each
    boundary.

    Args:
        boundaries: Handler boundaries from trace segmentation.
        model_path: Optional trained model path.

    Returns:
        One :class:`PredictionResult` per boundary, in order.
    """
    clf = build_handler_classifier(model_path)
    results: list[PredictionResult] = []
    for b in boundaries:
        data = {
            "handler_address": b.handler_address,
            "instruction_count": b.instruction_count,
            "vip_delta": b.vip_delta,
            "trace_start": b.trace_start,
            "trace_end": b.trace_end,
            "vip_value": b.vip_value,
        }
        results.append(clf.classify(data))
    return results
