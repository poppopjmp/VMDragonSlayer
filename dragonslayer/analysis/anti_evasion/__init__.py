"""Anti-Evasion Module — detect and neutralise anti-analysis techniques."""

from .environment_normalizer import (
    EnvironmentNormalizer,
    EvasionCategory,
    EvasionIndicator,
    NormalizationReport,
    Patch,
)

__all__ = [
    "EnvironmentNormalizer",
    "EvasionCategory",
    "EvasionIndicator",
    "NormalizationReport",
    "Patch",
]
