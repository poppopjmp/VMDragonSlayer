"""
Pattern Database Module

Provides persistent storage, indexing, and search for VM handler
byte-signature patterns.  Patterns are indexed by handler type,
architecture, and operation for fast multi-filter queries.
"""

import json
import logging
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class Architecture(Enum):
    """Supported architectures for patterns."""
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


class HandlerType(Enum):
    """VM handler categories."""
    ARITHMETIC = "arithmetic"
    BITWISE = "bitwise"
    MEMORY = "memory"
    CONTROL_FLOW = "control_flow"
    STACK = "stack"
    COMPARISON = "comparison"
    CONVERSION = "conversion"
    CRYPTO = "crypto"
    UNKNOWN = "unknown"


@dataclass
class Pattern:
    """A single VM handler byte-signature pattern.

    Attributes:
        pattern_id: Unique identifier for this pattern.
        name: Human-readable label (e.g. ``"vmp3_add_32"``).
        signature: Hex byte string, ``??`` for wildcards.
        architecture: Target arch (``x86``, ``x64``, ``arm``, …).
        handler_type: Semantic category (``arithmetic``, ``memory``, …).
        operation: Specific VM operation (``add``, ``load``, …).
        confidence: Match confidence weight in ``[0, 1]``.
        wildcards: Whether ``??`` wildcards are present.
        variants: Alternative byte signatures for the same handler.
        metadata: Arbitrary extra info (protector version, notes, …).
    """
    pattern_id: str
    name: str
    signature: str
    architecture: str
    handler_type: str
    operation: str
    confidence: float = 0.9
    wildcards: bool = True
    variants: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Validate pattern after initialization."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")

        if not self.pattern_id:
            raise ValueError("Pattern ID cannot be empty")

        if not self.signature:
            raise ValueError("Signature cannot be empty")

    def to_dict(self) -> dict[str, Any]:
        """Convert pattern to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> 'Pattern':
        """Create pattern from dictionary."""
        return cls(**data)

    def matches_architecture(self, arch: str) -> bool:
        """Check if pattern matches given architecture."""
        return self.architecture.lower() == arch.lower()

    def matches_handler_type(self, handler_type: str) -> bool:
        """Check if pattern matches given handler type."""
        return self.handler_type.lower() == handler_type.lower()

    def get_signature_bytes(self) -> list[str]:
        """
        Parse signature into list of bytes.

        """
        # Remove spaces and split by common separators
        sig = self.signature.replace(' ', '')
        # Split into pairs of hex characters or wildcards
        bytes_list = []
        i = 0
        while i < len(sig):
            if sig[i:i+2] == '??':
                bytes_list.append('??')
                i += 2
            elif sig[i:i+2].replace('|', '').strip():
                # Handle pipe separators
                byte = sig[i:i+2].replace('|', '').strip()
                if byte:
                    bytes_list.append(byte)
                i += 2
            else:
                i += 1
        return bytes_list


class PatternDatabase:
    """Indexed collection of VM handler patterns with JSON persistence.

    Maintains three secondary indices (by type, architecture, and
    operation) so that :meth:`search` can combine filters efficiently.
    """

    def __init__(self, database_path: Path | None = None) -> None:
        """Create a new database, optionally loading from *database_path*.

        Args:
            database_path: Path to a JSON file.  If it exists the
                patterns are loaded immediately.
        """
        self.patterns: dict[str, Pattern] = {}
        self.database_path = database_path
        self._index_by_type: dict[str, set[str]] = {}
        self._index_by_arch: dict[str, set[str]] = {}
        self._index_by_operation: dict[str, set[str]] = {}

        if database_path and database_path.exists():
            self.load(database_path)

    def add_pattern(self, pattern: Pattern) -> None:
        """Insert *pattern* into the database.

        Raises:
            ValueError: If a pattern with the same ``pattern_id`` already exists.
        """
        if pattern.pattern_id in self.patterns:
            raise ValueError(f"Pattern ID '{pattern.pattern_id}' already exists")

        self.patterns[pattern.pattern_id] = pattern
        self._update_indices(pattern)

        logger.info("Added pattern: %s (%s)", pattern.pattern_id, pattern.name)

    def get_pattern(self, pattern_id: str) -> Pattern | None:
        """Return the :class:`Pattern` with *pattern_id*, or ``None``."""
        return self.patterns.get(pattern_id)

    def update_pattern(self, pattern: Pattern) -> None:
        """Replace the pattern with the same ``pattern_id``.

        Raises:
            KeyError: If *pattern.pattern_id* is not in the database.
        """
        if pattern.pattern_id not in self.patterns:
            raise KeyError(f"Pattern ID '{pattern.pattern_id}' not found")

        # Remove old indices
        old_pattern = self.patterns[pattern.pattern_id]
        self._remove_from_indices(old_pattern)

        # Update pattern and indices
        self.patterns[pattern.pattern_id] = pattern
        self._update_indices(pattern)

        logger.info("Updated pattern: %s", pattern.pattern_id)

    def delete_pattern(self, pattern_id: str) -> bool:
        """Remove the pattern with *pattern_id*.

        Returns:
            ``True`` if the pattern was found and removed, ``False`` otherwise.
        """
        if pattern_id not in self.patterns:
            return False

        pattern = self.patterns[pattern_id]
        self._remove_from_indices(pattern)
        del self.patterns[pattern_id]

        logger.info("Deleted pattern: %s", pattern_id)
        return True

    def search_by_type(self, handler_type: str) -> list[Pattern]:
        """Return all patterns matching *handler_type* (case-insensitive)."""
        pattern_ids = self._index_by_type.get(handler_type.lower(), set())
        return [self.patterns[pid] for pid in pattern_ids]

    def search_by_architecture(self, architecture: str) -> list[Pattern]:
        """Return all patterns matching *architecture* (case-insensitive)."""
        pattern_ids = self._index_by_arch.get(architecture.lower(), set())
        return [self.patterns[pid] for pid in pattern_ids]

    def search_by_operation(self, operation: str) -> list[Pattern]:
        """Return all patterns matching *operation* (case-insensitive)."""
        pattern_ids = self._index_by_operation.get(operation.lower(), set())
        return [self.patterns[pid] for pid in pattern_ids]

    def search(
        self,
        handler_type: str | None = None,
        architecture: str | None = None,
        operation: str | None = None,
        min_confidence: float = 0.0,
    ) -> list[Pattern]:
        """Multi-filter search across indexed fields.

        Args:
            handler_type: Filter by handler type (e.g. ``"arithmetic"``).
            architecture: Filter by architecture (e.g. ``"x64"``).
            operation: Filter by VM operation (e.g. ``"add"``).
            min_confidence: Exclude patterns below this threshold.

        Returns:
            List of :class:`Pattern` objects matching **all** active filters.
        """
        # Start with all patterns
        results = set(self.patterns.keys())

        # Apply filters
        if handler_type:
            results &= self._index_by_type.get(handler_type.lower(), set())

        if architecture:
            results &= self._index_by_arch.get(architecture.lower(), set())

        if operation:
            results &= self._index_by_operation.get(operation.lower(), set())

        # Filter by confidence
        patterns = [self.patterns[pid] for pid in results]
        if min_confidence > 0.0:
            patterns = [p for p in patterns if p.confidence >= min_confidence]

        return patterns

    def get_all_patterns(self) -> list[Pattern]:
        """
        Get all patterns in the database.

        """
        return list(self.patterns.values())

    def get_statistics(self) -> dict[str, Any]:
        """Return a summary dict with counts by type, architecture, and operation."""
        return {
            'total_patterns': len(self.patterns),
            'by_type': {k: len(v) for k, v in self._index_by_type.items()},
            'by_architecture': {k: len(v) for k, v in self._index_by_arch.items()},
            'by_operation': {k: len(v) for k, v in self._index_by_operation.items()},
            'avg_confidence': sum(p.confidence for p in self.patterns.values()) / len(self.patterns) if self.patterns else 0.0
        }

    def load(self, path: Path) -> int:
        """
        Load patterns from JSON file.

        """
        if not path.exists():
            raise FileNotFoundError(f"Database file not found: {path}")

        with open(path, encoding='utf-8') as f:
            data = json.load(f)

        # Clear existing data
        self.patterns.clear()
        self._index_by_type.clear()
        self._index_by_arch.clear()
        self._index_by_operation.clear()

        # Load patterns
        patterns_data = data.get('patterns', [])
        for pattern_dict in patterns_data:
            try:
                pattern = Pattern.from_dict(pattern_dict)
                self.add_pattern(pattern)
            except (ValueError, TypeError, KeyError) as e:
                logger.warning("Failed to load pattern %s: %s", pattern_dict.get('pattern_id', 'unknown'), e)

        self.database_path = path
        logger.info("Loaded %d patterns from %s", len(self.patterns), path)
        return len(self.patterns)

    def save(self, path: Path | None = None) -> None:
        """
        Save patterns to JSON file.

        """
        save_path = path or self.database_path
        if not save_path:
            raise ValueError("No path provided for saving database")

        # Ensure directory exists
        save_path.parent.mkdir(parents=True, exist_ok=True)

        # Convert patterns to dict
        data = {
            'version': '1.0',
            'patterns': [p.to_dict() for p in self.patterns.values()]
        }

        with open(save_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)

        logger.info("Saved %d patterns to %s", len(self.patterns), save_path)

    def _update_indices(self, pattern: Pattern) -> None:
        """Update search indices for a pattern."""
        # Index by type
        handler_type = pattern.handler_type.lower()
        if handler_type not in self._index_by_type:
            self._index_by_type[handler_type] = set()
        self._index_by_type[handler_type].add(pattern.pattern_id)

        # Index by architecture
        arch = pattern.architecture.lower()
        if arch not in self._index_by_arch:
            self._index_by_arch[arch] = set()
        self._index_by_arch[arch].add(pattern.pattern_id)

        # Index by operation
        op = pattern.operation.lower()
        if op not in self._index_by_operation:
            self._index_by_operation[op] = set()
        self._index_by_operation[op].add(pattern.pattern_id)

    def _remove_from_indices(self, pattern: Pattern) -> None:
        """Remove pattern from search indices."""
        # Remove from type index
        handler_type = pattern.handler_type.lower()
        if handler_type in self._index_by_type:
            self._index_by_type[handler_type].discard(pattern.pattern_id)

        # Remove from architecture index
        arch = pattern.architecture.lower()
        if arch in self._index_by_arch:
            self._index_by_arch[arch].discard(pattern.pattern_id)

        # Remove from operation index
        op = pattern.operation.lower()
        if op in self._index_by_operation:
            self._index_by_operation[op].discard(pattern.pattern_id)

    def __len__(self) -> int:
        """Return number of patterns in database."""
        return len(self.patterns)

    def __contains__(self, pattern_id: str) -> bool:
        """Check if pattern_id exists in database."""
        return pattern_id in self.patterns

    def __iter__(self) -> "Iterator[Pattern]":
        """Iterate over all patterns."""
        return iter(self.patterns.values())
