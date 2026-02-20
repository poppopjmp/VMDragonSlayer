"""
Pattern Analysis Module

"""

from .database import (
    Pattern,
    PatternDatabase,
    Architecture,
    HandlerType
)

from .recognizer import (
    Match,
    PatternRecognizer,
    SequenceRecognizer
)

from .classifier import (
    PatternClassifier,
    ClassificationResult,
    ClassificationReport,
    strip_junk,
    normalize_operands,
    _is_junk_instruction,
    _match_instruction_sequence_gap,
)

from .yara_engine import (
    YaraEngine,
    YaraMatch,
    YARA_AVAILABLE,
)

from .matcher import (
    PatternMatcher,
    RankedMatch,
    MatchContext,
    find_signature_collisions,
)

from .version_fingerprint import (
    VMProtectVersionFingerprinter,
    VMProtectVersion,
    VersionFingerprint,
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

    # Version Fingerprinting
    'VMProtectVersionFingerprinter',
    'VMProtectVersion',
    'VersionFingerprint',

    # YARA
    'YaraEngine',
    'YaraMatch',
    'YARA_AVAILABLE',
]
