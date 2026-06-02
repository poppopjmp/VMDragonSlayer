"""
Pattern Analysis Module

"""

from .classifier import (
    ClassificationReport,
    ClassificationResult,
    PatternClassifier,
    _is_junk_instruction,
    _match_instruction_sequence_gap,
    normalize_operands,
    strip_junk,
)
from .database import Architecture, HandlerType, Pattern, PatternDatabase
from .matcher import (
    MatchContext,
    PatternMatcher,
    RankedMatch,
    find_signature_collisions,
)
from .recognizer import Match, PatternRecognizer, SequenceRecognizer
from .version_fingerprint import (
    VersionFingerprint,
    VMProtectVersion,
    VMProtectVersionFingerprinter,
)
from .yara_engine import (
    YARA_AVAILABLE,
    YaraEngine,
    YaraMatch,
)

__all__ = [
    # Database
    'Pattern',
    'PatternDatabase',
    'Architecture',
    'HandlerType',

    # Recognition
    'Match',
    'PatternRecognizer',
    'SequenceRecognizer',

    # Context-Aware Matching
    'PatternMatcher',
    'RankedMatch',
    'MatchContext',
    'find_signature_collisions',

    # Classification
    'PatternClassifier',
    'ClassificationResult',
    'ClassificationReport',
    'strip_junk',
    'normalize_operands',
    '_is_junk_instruction',
    '_match_instruction_sequence_gap',

    # Version Fingerprinting
    'VMProtectVersionFingerprinter',
    'VMProtectVersion',
    'VersionFingerprint',

    # YARA
    'YaraEngine',
    'YaraMatch',
    'YARA_AVAILABLE',
]
