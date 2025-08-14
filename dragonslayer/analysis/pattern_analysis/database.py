# VMDragonSlayer - Advanced VM detection and analysis library
# Copyright (C) 2025 van1sh
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
Pattern Database
===============

Unified pattern database for VM bytecode pattern storage and retrieval.

This module consolidates pattern database functionality from multiple
implementations into a single, production-ready database.
"""

import json
import logging
import sqlite3
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ...core.config import VMDragonSlayerConfig
from ...core.exceptions import (
    ConfigurationError,
    PatternAnalysisError,
)

logger = logging.getLogger(__name__)


class PatternType(Enum):
    """Types of VM patterns"""

    HANDLER = "handler"
    OPCODE = "opcode"
    STRUCTURE = "structure"
    CONTROL_FLOW = "control_flow"
    OBFUSCATION = "obfuscation"
    ARITHMETIC = "arithmetic"
    BITWISE = "bitwise"
    MEMORY = "memory"
    STACK = "stack"


class PatternStatus(Enum):
    """Pattern status in database"""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    EXPERIMENTAL = "experimental"
    VERIFIED = "verified"


@dataclass
class PatternSample:
    """Sample pattern for VM detection and analysis"""

    pattern_id: str
    pattern_type: PatternType
    bytecode: bytes
    description: str
    vm_family: str
    confidence: float
    vm_type: str = "generic"
    status: PatternStatus = PatternStatus.ACTIVE
    metadata: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    usage_count: int = 0

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = self.created_at
        if self.metadata is None:
            self.metadata = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = asdict(self)
        # Convert enums to values
        data["pattern_type"] = self.pattern_type.value
        data["status"] = self.status.value
        # Convert bytes to hex
        data["bytecode"] = self.bytecode.hex()
        # Convert datetimes to ISO format
        if self.created_at:
            data["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            data["updated_at"] = self.updated_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PatternSample":
        """Create from dictionary"""
        # Convert values back to proper types
        data = data.copy()
        data["pattern_type"] = PatternType(data["pattern_type"])
        data["status"] = PatternStatus(data.get("status", "active"))
        data["bytecode"] = bytes.fromhex(data["bytecode"])

        # Convert datetime strings
        if data.get("created_at"):
            data["created_at"] = datetime.fromisoformat(data["created_at"])
        if data.get("updated_at"):
            data["updated_at"] = datetime.fromisoformat(data["updated_at"])

        return cls(**data)


@dataclass
class PatternMatch:
    """Result of pattern matching operation"""

    pattern_id: str
    confidence: float
    location: int
    length: int
    context: Dict[str, Any]
    match_type: str = "exact"
    similarity_score: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return asdict(self)


class PatternDatabase:
    """Database of VM patterns for detection and analysis"""

    def __init__(self, config: Optional[VMDragonSlayerConfig] = None):
        """Initialize pattern database

        Args:
            config: VMDragonSlayer configuration
        """
        self.config = config or VMDragonSlayerConfig()
        self.patterns: Dict[str, PatternSample] = {}
        self.pattern_index: Dict[str, List[str]] = {}
        self.db_path = None
        self._connection = None

        # Set up database path
        if hasattr(self.config, "pattern_analysis"):
            self.db_path = getattr(self.config.pattern_analysis, "database_path", None)

        if not self.db_path:
            self.db_path = "data/pattern_database.db"

        # Initialize database
        self._initialize_database()

        # Load default patterns
        self._load_default_patterns()

        # Load from database if exists
        self._load_from_database()

        logger.info("Pattern database initialized with %d patterns", len(self.patterns))

    def _initialize_database(self):
        """Initialize SQLite database"""
        try:
            # Ensure directory exists
            db_path = Path(self.db_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)

            self._connection = sqlite3.connect(str(db_path))
            cursor = self._connection.cursor()

            # Create patterns table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS patterns (
                    pattern_id TEXT PRIMARY KEY,
                    pattern_type TEXT NOT NULL,
                    bytecode_hex TEXT NOT NULL,
                    description TEXT NOT NULL,
                    vm_family TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    vm_type TEXT DEFAULT 'generic',
                    status TEXT DEFAULT 'active',
                    metadata TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    usage_count INTEGER DEFAULT 0
                )
            """
            )

            # Create indexes
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_pattern_type ON patterns(pattern_type)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_vm_family ON patterns(vm_family)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_confidence ON patterns(confidence)"
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_status ON patterns(status)")

            self._connection.commit()

        except Exception as e:
            logger.error("Failed to initialize pattern database: %s", e)
            raise ConfigurationError(f"Database initialization failed: {e}")

    def _load_default_patterns(self):
        """Load default patterns"""
        default_patterns = [
            PatternSample(
                pattern_id="vm_add_pattern",
                pattern_type=PatternType.ARITHMETIC,
                bytecode=bytes([0x50, 0x00, 0x50, 0x01, 0x51]),  # PUSH 0, PUSH 1, ADD
                description="VM addition operation pattern",
                vm_family="generic",
                confidence=0.8,
                vm_type="stack_vm",
                metadata={
                    "instruction_count": 3,
                    "stack_effect": -1,
                    "semantic": "addition",
                },
            ),
            PatternSample(
                pattern_id="vm_xor_pattern",
                pattern_type=PatternType.BITWISE,
                bytecode=bytes([0x50, 0x00, 0x50, 0x01, 0x54]),  # PUSH 0, PUSH 1, XOR
                description="VM XOR operation pattern",
                vm_family="generic",
                confidence=0.8,
                vm_type="stack_vm",
                metadata={
                    "instruction_count": 3,
                    "stack_effect": -1,
                    "semantic": "xor",
                },
            ),
            PatternSample(
                pattern_id="vm_conditional_jump",
                pattern_type=PatternType.CONTROL_FLOW,
                bytecode=bytes([0x56, 0x00, 0x57, 0x10]),  # CMP 0, JMP 0x10
                description="VM conditional jump pattern",
                vm_family="generic",
                confidence=0.75,
                vm_type="register_vm",
                metadata={
                    "instruction_count": 2,
                    "control_flow": True,
                    "semantic": "conditional_branch",
                },
            ),
            PatternSample(
                pattern_id="mba_obfuscation",
                pattern_type=PatternType.OBFUSCATION,
                bytecode=bytes([0x50, 0x00, 0x50, 0x01, 0x54, 0x50, 0x02, 0x55, 0x51]),
                description="Mixed Boolean-Arithmetic obfuscation pattern",
                vm_family="obfuscated",
                confidence=0.9,
                vm_type="obfuscated_vm",
                metadata={
                    "instruction_count": 5,
                    "obfuscation_type": "mba",
                    "deobfuscated_semantic": "addition",
                },
            ),
        ]

        for pattern in default_patterns:
            self.add_pattern(pattern)

    def _load_from_database(self):
        """Load patterns from SQLite database"""
        if not self._connection:
            return

        try:
            cursor = self._connection.cursor()
            cursor.execute("SELECT * FROM patterns WHERE status = ?", ("active",))

            for row in cursor.fetchall():
                pattern_data = {
                    "pattern_id": row[0],
                    "pattern_type": row[1],
                    "bytecode": row[2],  # hex string
                    "description": row[3],
                    "vm_family": row[4],
                    "confidence": row[5],
                    "vm_type": row[6],
                    "status": row[7],
                    "metadata": json.loads(row[8]) if row[8] else {},
                    "created_at": row[9],
                    "updated_at": row[10],
                    "usage_count": row[11],
                }

                pattern = PatternSample.from_dict(pattern_data)
                self.patterns[pattern.pattern_id] = pattern
                self._update_index(pattern)

        except Exception as e:
            logger.error("Failed to load patterns from database: %s", e)

    def add_pattern(self, pattern: Union[PatternSample, tuple]) -> None:
        """Add a pattern to the database

        Args:
            pattern: PatternSample object or legacy tuple format
        """
        if isinstance(pattern, PatternSample):
            # New API - PatternSample object
            pattern.updated_at = datetime.now()
            self.patterns[pattern.pattern_id] = pattern
            self._update_index(pattern)
            self._save_pattern_to_db(pattern)

        elif isinstance(pattern, tuple) and len(pattern) == 3:
            # Legacy API - (pattern_id, features, label) tuple
            pattern_id, features, label = pattern

            # Convert to PatternSample
            bytecode = (
                features if isinstance(features, bytes) else str(features).encode()
            )
            pattern_sample = PatternSample(
                pattern_id=pattern_id,
                pattern_type=PatternType.HANDLER,  # Default type
                bytecode=bytecode,
                description=f"Legacy pattern: {label}",
                vm_family=label,
                confidence=0.8,  # Default confidence
                vm_type="legacy",
            )

            self.add_pattern(pattern_sample)

        else:
            raise PatternAnalysisError(f"Invalid pattern format: {type(pattern)}")

        logger.debug(
            "Added pattern: %s",
            pattern.pattern_id if isinstance(pattern, PatternSample) else pattern_id,
        )

    def _update_index(self, pattern: PatternSample):
        """Update pattern index"""
        pattern_type = pattern.pattern_type.value
        if pattern_type not in self.pattern_index:
            self.pattern_index[pattern_type] = []

        if pattern.pattern_id not in self.pattern_index[pattern_type]:
            self.pattern_index[pattern_type].append(pattern.pattern_id)

    def _save_pattern_to_db(self, pattern: PatternSample):
        """Save pattern to SQLite database"""
        if not self._connection:
            return

        try:
            cursor = self._connection.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO patterns
                (pattern_id, pattern_type, bytecode_hex, description, vm_family,
                 confidence, vm_type, status, metadata, created_at, updated_at, usage_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    pattern.pattern_id,
                    pattern.pattern_type.value,
                    pattern.bytecode.hex(),
                    pattern.description,
                    pattern.vm_family,
                    pattern.confidence,
                    pattern.vm_type,
                    pattern.status.value,
                    json.dumps(pattern.metadata),
                    pattern.created_at.isoformat() if pattern.created_at else None,
                    pattern.updated_at.isoformat() if pattern.updated_at else None,
                    pattern.usage_count,
                ),
            )

            self._connection.commit()

        except Exception as e:
            logger.error("Failed to save pattern to database: %s", e)

    def get_pattern(self, pattern_id: str) -> Optional[PatternSample]:
        """Get a pattern by ID

        Args:
            pattern_id: Pattern identifier

        Returns:
            Pattern if found, None otherwise
        """
        pattern = self.patterns.get(pattern_id)
        if pattern:
            # Update usage count
            pattern.usage_count += 1
            self._save_pattern_to_db(pattern)
        return pattern

    def search_patterns(
        self,
        vm_family: Optional[str] = None,
        pattern_type: Optional[PatternType] = None,
        min_confidence: float = 0.0,
        status: Optional[PatternStatus] = None,
    ) -> List[PatternSample]:
        """Search patterns by criteria

        Args:
            vm_family: Filter by VM family
            pattern_type: Filter by pattern type
            min_confidence: Minimum confidence threshold
            status: Filter by pattern status

        Returns:
            List of matching patterns sorted by confidence
        """
        results = []

        for pattern in self.patterns.values():
            # Filter by VM family
            if vm_family and pattern.vm_family.lower() != vm_family.lower():
                continue

            # Filter by pattern type
            if pattern_type and pattern.pattern_type != pattern_type:
                continue

            # Filter by confidence
            if pattern.confidence < min_confidence:
                continue

            # Filter by status
            if status and pattern.status != status:
                continue

            results.append(pattern)

        # Sort by confidence (highest first)
        results.sort(key=lambda p: p.confidence, reverse=True)
        return results

    async def match_patterns(
        self, data: bytes, threshold: float = 0.7, max_matches: int = 100
    ) -> List[PatternMatch]:
        """Match patterns against binary data

        Args:
            data: Binary data to search
            threshold: Confidence threshold for matches
            max_matches: Maximum number of matches to return

        Returns:
            List of pattern matches
        """
        matches = []

        try:
            for pattern in self.patterns.values():
                if pattern.status != PatternStatus.ACTIVE:
                    continue

                pattern_bytes = pattern.bytecode

                if len(pattern_bytes) > len(data):
                    continue

                # Simple substring matching (could be enhanced with fuzzy matching)
                for i in range(len(data) - len(pattern_bytes) + 1):
                    if data[i : i + len(pattern_bytes)] == pattern_bytes:
                        confidence = pattern.confidence

                        if confidence >= threshold:
                            match = PatternMatch(
                                pattern_id=pattern.pattern_id,
                                confidence=confidence,
                                location=i,
                                length=len(pattern_bytes),
                                context={
                                    "vm_family": pattern.vm_family,
                                    "pattern_type": pattern.pattern_type.value,
                                    "description": pattern.description,
                                    "vm_type": pattern.vm_type,
                                    "metadata": pattern.metadata,
                                },
                            )
                            matches.append(match)

                            # Update usage count
                            pattern.usage_count += 1

                            if len(matches) >= max_matches:
                                break

                if len(matches) >= max_matches:
                    break

            # Sort by confidence (highest first)
            matches.sort(key=lambda m: m.confidence, reverse=True)

        except Exception as e:
            logger.error("Pattern matching error: %s", e)
            raise PatternAnalysisError(f"Pattern matching failed: {e}")

        return matches

    def update_pattern(self, pattern_id: str, **updates) -> bool:
        """Update pattern fields

        Args:
            pattern_id: Pattern to update
            **updates: Fields to update

        Returns:
            True if updated, False if pattern not found
        """
        pattern = self.patterns.get(pattern_id)
        if not pattern:
            return False

        # Update allowed fields
        allowed_fields = {"description", "confidence", "vm_type", "status", "metadata"}

        for field, value in updates.items():
            if field in allowed_fields:
                if field == "status" and isinstance(value, str):
                    value = PatternStatus(value)
                setattr(pattern, field, value)

        pattern.updated_at = datetime.now()
        self._save_pattern_to_db(pattern)

        return True

    def delete_pattern(self, pattern_id: str) -> bool:
        """Delete pattern from database

        Args:
            pattern_id: Pattern to delete

        Returns:
            True if deleted, False if not found
        """
        if pattern_id not in self.patterns:
            return False

        # Remove from memory
        pattern = self.patterns.pop(pattern_id)

        # Remove from index
        pattern_type = pattern.pattern_type.value
        if pattern_type in self.pattern_index:
            self.pattern_index[pattern_type] = [
                p for p in self.pattern_index[pattern_type] if p != pattern_id
            ]

        # Remove from database
        if self._connection:
            try:
                cursor = self._connection.cursor()
                cursor.execute(
                    "DELETE FROM patterns WHERE pattern_id = ?", (pattern_id,)
                )
                self._connection.commit()
            except Exception as e:
                logger.error("Failed to delete pattern from database: %s", e)

        return True

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics

        Returns:
            Dictionary of statistics
        """
        stats = {
            "total_patterns": len(self.patterns),
            "by_type": {},
            "by_vm_family": {},
            "by_status": {},
            "average_confidence": 0.0,
            "most_used_patterns": [],
        }

        # Count by type, family, status
        for pattern in self.patterns.values():
            pattern_type = pattern.pattern_type.value
            stats["by_type"][pattern_type] = stats["by_type"].get(pattern_type, 0) + 1

            vm_family = pattern.vm_family
            stats["by_vm_family"][vm_family] = (
                stats["by_vm_family"].get(vm_family, 0) + 1
            )

            status = pattern.status.value
            stats["by_status"][status] = stats["by_status"].get(status, 0) + 1

        # Calculate average confidence
        if self.patterns:
            total_confidence = sum(p.confidence for p in self.patterns.values())
            stats["average_confidence"] = total_confidence / len(self.patterns)

        # Most used patterns
        sorted_patterns = sorted(
            self.patterns.values(), key=lambda p: p.usage_count, reverse=True
        )
        stats["most_used_patterns"] = [
            {
                "pattern_id": p.pattern_id,
                "usage_count": p.usage_count,
                "confidence": p.confidence,
            }
            for p in sorted_patterns[:10]
        ]

        return stats

    def export_patterns(self, file_path: str, format: str = "json") -> None:
        """Export patterns to file

        Args:
            file_path: Output file path
            format: Export format ("json" or "csv")
        """
        try:
            if format.lower() == "json":
                self._export_json(file_path)
            elif format.lower() == "csv":
                self._export_csv(file_path)
            else:
                raise PatternAnalysisError(f"Unsupported export format: {format}")

        except Exception as e:
            logger.error("Pattern export failed: %s", e)
            raise PatternAnalysisError(f"Export failed: {e}")

    def _export_json(self, file_path: str):
        """Export patterns to JSON"""
        patterns_data = [pattern.to_dict() for pattern in self.patterns.values()]

        data = {
            "version": "2.0",
            "exported_at": datetime.now().isoformat(),
            "total_patterns": len(patterns_data),
            "patterns": patterns_data,
        }

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _export_csv(self, file_path: str):
        """Export patterns to CSV"""
        import csv

        with open(file_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)

            # Write header
            writer.writerow(
                [
                    "pattern_id",
                    "pattern_type",
                    "vm_family",
                    "confidence",
                    "description",
                    "vm_type",
                    "status",
                    "usage_count",
                ]
            )

            # Write patterns
            for pattern in self.patterns.values():
                writer.writerow(
                    [
                        pattern.pattern_id,
                        pattern.pattern_type.value,
                        pattern.vm_family,
                        pattern.confidence,
                        pattern.description,
                        pattern.vm_type,
                        pattern.status.value,
                        pattern.usage_count,
                    ]
                )

    def import_patterns(self, file_path: str) -> int:
        """Import patterns from file

        Args:
            file_path: Input file path

        Returns:
            Number of patterns imported
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)

            imported_count = 0
            for pattern_data in data.get("patterns", []):
                try:
                    pattern = PatternSample.from_dict(pattern_data)
                    self.add_pattern(pattern)
                    imported_count += 1
                except Exception as e:
                    logger.warning(
                        "Failed to import pattern %s: %s",
                        pattern_data.get("pattern_id", "unknown"),
                        e,
                    )

            logger.info("Imported %d patterns from %s", imported_count, file_path)
            return imported_count

        except Exception as e:
            logger.error("Pattern import failed: %s", e)
            raise PatternAnalysisError(f"Import failed: {e}")

    def close(self):
        """Close database connection"""
        if self._connection:
            self._connection.close()
            self._connection = None

    def __del__(self):
        """Cleanup on deletion"""
        self.close()
