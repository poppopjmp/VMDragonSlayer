"""Anti-Evasion Module — detect and neutralise anti-analysis techniques."""

from .environment_normalizer import (
    EnvironmentNormalizer,
    EvasionCategory,
    EvasionIndicator,
    NormalizationReport,
    Patch,
)
from .runtime_hooks import (
    HookCategory,
    HookDescriptor,
    HookInstallResult,
    HookSet,
    TimingState,
    apply_hooks_to_angr,
    apply_hooks_to_qiling,
    apply_hooks_to_triton,
    build_hook_set,
    build_hook_set_from_report,
    hooks_for_binary,
)

__all__ = [
    "EnvironmentNormalizer",
    "EvasionCategory",
    "EvasionIndicator",
    "NormalizationReport",
    "Patch",
    "HookCategory",
    "HookDescriptor",
    "HookSet",
    "HookInstallResult",
    "TimingState",
    "build_hook_set",
    "build_hook_set_from_report",
    "hooks_for_binary",
    "apply_hooks_to_qiling",
    "apply_hooks_to_angr",
    "apply_hooks_to_triton",
]
