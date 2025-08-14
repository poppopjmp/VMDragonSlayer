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
Pattern Classifier
==================

Unified machine learning pattern classifier for VM bytecode analysis.

This module consolidates pattern classification functionality from multiple
implementations into a single, production-ready classifier.
"""

import asyncio
import hashlib
import json
import logging
import threading
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np

from ..core.config import VMDragonSlayerConfig
from ..core.exceptions import (
    MLError,
    PatternAnalysisError,
)

logger = logging.getLogger(__name__)

# Handle optional dependencies gracefully
try:
    import torch
    import torch.nn as nn

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    logger.warning("PyTorch not available, using fallback methods")

try:
    import joblib
    from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("Scikit-learn not available, using rule-based classification")


@dataclass
class PatternFeatures:
    """Feature vector for VM pattern analysis."""

    instruction_count: int = 0
    unique_opcodes: int = 0
    control_flow_complexity: float = 0.0
    data_access_patterns: int = 0
    arithmetic_operations: int = 0
    logical_operations: int = 0
    memory_operations: int = 0
    stack_operations: int = 0
    crypto_operations: int = 0
    string_operations: int = 0
    register_usage_density: float = 0.0
    execution_frequency: float = 1.0
    taint_propagation_complexity: float = 0.0
    symbolic_depth: int = 0

    def to_vector(self) -> np.ndarray:
        """Convert features to numpy array for ML models."""
        return np.array(
            [
                self.instruction_count,
                self.unique_opcodes,
                self.control_flow_complexity,
                self.data_access_patterns,
                self.arithmetic_operations,
                self.logical_operations,
                self.memory_operations,
                self.stack_operations,
                self.crypto_operations,
                self.string_operations,
                self.register_usage_density,
                self.execution_frequency,
                self.taint_propagation_complexity,
                self.symbolic_depth,
            ]
        )

    def to_dict(self) -> Dict[str, Union[int, float]]:
        """Convert features to dictionary."""
        return asdict(self)


@dataclass
class ClassificationResult:
    """Result of pattern classification."""

    pattern_type: str
    confidence: float
    vm_family: str
    complexity: str
    handler_type: str
    method: str  # 'ml', 'similarity', 'rules'
    features: PatternFeatures
    timestamp: datetime

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        result = asdict(self)
        result["features"] = self.features.to_dict()
        result["timestamp"] = self.timestamp.isoformat()
        return result


class FeatureExtractor:
    """Extract features from VM bytecode for classification."""

    def __init__(self):
        self.opcode_stats = {}

    def extract_from_bytecode(
        self,
        bytecode: bytes,
        taint_info: Optional[Dict] = None,
        symbolic_info: Optional[Dict] = None,
    ) -> PatternFeatures:
        """Extract features from bytecode with optional taint and symbolic information."""
        if not bytecode:
            return PatternFeatures()

        # Basic bytecode analysis
        instruction_count = len(bytecode)
        unique_opcodes = len(set(bytecode))

        # Calculate complexity metrics
        control_flow_complexity = self._calculate_control_flow_complexity(bytecode)
        register_usage_density = self._calculate_register_usage(bytecode)

        # Count operation types
        arithmetic_ops = self._count_arithmetic_operations(bytecode)
        logical_ops = self._count_logical_operations(bytecode)
        memory_ops = self._count_memory_operations(bytecode)
        stack_ops = self._count_stack_operations(bytecode)
        crypto_ops = self._count_crypto_operations(bytecode)
        string_ops = self._count_string_operations(bytecode)

        # Enhanced metrics from taint tracking
        taint_complexity = 0.0
        if taint_info:
            taint_complexity = taint_info.get("propagation_complexity", 0.0)

        # Enhanced metrics from symbolic execution
        symbolic_depth = 0
        if symbolic_info:
            symbolic_depth = symbolic_info.get("max_depth", 0)

        return PatternFeatures(
            instruction_count=instruction_count,
            unique_opcodes=unique_opcodes,
            control_flow_complexity=control_flow_complexity,
            data_access_patterns=memory_ops + stack_ops,
            arithmetic_operations=arithmetic_ops,
            logical_operations=logical_ops,
            memory_operations=memory_ops,
            stack_operations=stack_ops,
            crypto_operations=crypto_ops,
            string_operations=string_ops,
            register_usage_density=register_usage_density,
            execution_frequency=1.0,  # Default, could be enhanced with profiling
            taint_propagation_complexity=taint_complexity,
            symbolic_depth=symbolic_depth,
        )

    def _calculate_control_flow_complexity(self, bytecode: bytes) -> float:
        """Calculate control flow complexity based on jump patterns."""
        if len(bytecode) < 2:
            return 0.0

        # Look for jump-like patterns in bytecode
        jump_opcodes = {
            0x70,
            0x71,
            0x72,
            0x73,
            0x74,
            0x75,
            0x76,
            0x77,  # conditional jumps
            0xEB,
            0xE9,
            0xEA,
            0xFF,
        }  # unconditional jumps and calls

        jumps = sum(1 for byte in bytecode if byte in jump_opcodes)
        return jumps / len(bytecode) * 10.0  # Normalize and scale

    def _calculate_register_usage(self, bytecode: bytes) -> float:
        """Calculate register usage density."""
        if len(bytecode) < 2:
            return 0.0

        # Count register-related opcodes (simplified heuristic)
        register_opcodes = set(range(0x40, 0x50)) | set(range(0x50, 0x60))
        register_uses = sum(1 for byte in bytecode if byte in register_opcodes)
        return register_uses / len(bytecode)

    def _count_arithmetic_operations(self, bytecode: bytes) -> int:
        """Count arithmetic operations in bytecode."""
        arithmetic_opcodes = {0x01, 0x03, 0x05, 0x29, 0x2B, 0x2D}  # ADD, SUB variants
        return sum(1 for byte in bytecode if byte in arithmetic_opcodes)

    def _count_logical_operations(self, bytecode: bytes) -> int:
        """Count logical operations in bytecode."""
        logical_opcodes = {0x21, 0x23, 0x25, 0x31, 0x33, 0x35}  # AND, OR, XOR variants
        return sum(1 for byte in bytecode if byte in logical_opcodes)

    def _count_memory_operations(self, bytecode: bytes) -> int:
        """Count memory access operations."""
        memory_opcodes = {0x8B, 0x89, 0x8A, 0x88, 0xA1, 0xA3}  # MOV variants
        return sum(1 for byte in bytecode if byte in memory_opcodes)

    def _count_stack_operations(self, bytecode: bytes) -> int:
        """Count stack operations."""
        stack_opcodes = {
            0x50,
            0x51,
            0x52,
            0x53,
            0x54,
            0x55,
            0x56,
            0x57,  # PUSH
            0x58,
            0x59,
            0x5A,
            0x5B,
            0x5C,
            0x5D,
            0x5E,
            0x5F,
        }  # POP
        return sum(1 for byte in bytecode if byte in stack_opcodes)

    def _count_crypto_operations(self, bytecode: bytes) -> int:
        """Count cryptographic operations (heuristic)."""
        # This is a simplified heuristic - real crypto detection would be more complex
        crypto_patterns = [b"\xae", b"\xa6", b"\xa7"]  # SCAS, CMPS, etc.
        count = 0
        for pattern in crypto_patterns:
            count += bytecode.count(pattern)
        return count

    def _count_string_operations(self, bytecode: bytes) -> int:
        """Count string operations."""
        string_opcodes = {0xA4, 0xA5, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF}
        return sum(1 for byte in bytecode if byte in string_opcodes)


class PatternDatabase:
    """Pattern database for similarity-based classification."""

    def __init__(self, db_path: str = "data/pattern_database.json"):
        self.db_path = Path(db_path)
        self.patterns: Dict[str, Dict] = {}
        self._lock = threading.RLock()
        self.load_database()

    def load_database(self):
        """Load pattern database from file."""
        with self._lock:
            if self.db_path.exists():
                try:
                    with open(self.db_path) as f:
                        self.patterns = json.load(f)
                    logger.info(f"Loaded {len(self.patterns)} patterns from database")
                except Exception as e:
                    logger.error(f"Failed to load pattern database: {e}")
                    self._initialize_default_patterns()
            else:
                logger.info("Initializing new pattern database")
                self._initialize_default_patterns()

    def _initialize_default_patterns(self):
        """Initialize with known VM patterns."""
        self.patterns = {
            "VM_ADD": {
                "description": "Virtual machine ADD operation",
                "features": {
                    "instruction_count": 8,
                    "unique_opcodes": 4,
                    "control_flow_complexity": 2.1,
                    "arithmetic_operations": 3,
                    "stack_operations": 2,
                },
                "vm_family": "Generic",
                "complexity": "Simple",
                "handler_type": "Arithmetic",
            },
            "VM_XOR": {
                "description": "Virtual machine XOR operation",
                "features": {
                    "instruction_count": 6,
                    "unique_opcodes": 3,
                    "control_flow_complexity": 1.5,
                    "logical_operations": 2,
                    "stack_operations": 1,
                },
                "vm_family": "Generic",
                "complexity": "Simple",
                "handler_type": "Logical",
            },
            "VM_LOAD": {
                "description": "Virtual machine memory load operation",
                "features": {
                    "instruction_count": 10,
                    "unique_opcodes": 5,
                    "control_flow_complexity": 2.8,
                    "memory_operations": 4,
                    "stack_operations": 3,
                },
                "vm_family": "Generic",
                "complexity": "Medium",
                "handler_type": "Memory",
            },
        }
        self.save_database()

    def save_database(self):
        """Save pattern database to file."""
        with self._lock:
            try:
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.db_path, "w") as f:
                    json.dump(self.patterns, f, indent=2)
                logger.debug("Pattern database saved")
            except Exception as e:
                logger.error(f"Failed to save pattern database: {e}")

    def get_similar_patterns(
        self, features: PatternFeatures, threshold: float = 0.8
    ) -> List[Tuple[str, float]]:
        """Find similar patterns using feature similarity."""
        feature_vector = features.to_vector()
        similarities = []

        with self._lock:
            for pattern_id, pattern_data in self.patterns.items():
                pattern_features = pattern_data.get("features", {})
                if not pattern_features:
                    continue

                # Create feature vector from pattern
                pattern_vector = np.array(
                    [
                        pattern_features.get("instruction_count", 0),
                        pattern_features.get("unique_opcodes", 0),
                        pattern_features.get("control_flow_complexity", 0.0),
                        pattern_features.get("data_access_patterns", 0),
                        pattern_features.get("arithmetic_operations", 0),
                        pattern_features.get("logical_operations", 0),
                        pattern_features.get("memory_operations", 0),
                        pattern_features.get("stack_operations", 0),
                        pattern_features.get("crypto_operations", 0),
                        pattern_features.get("string_operations", 0),
                        pattern_features.get("register_usage_density", 0.0),
                        pattern_features.get("execution_frequency", 1.0),
                        pattern_features.get("taint_propagation_complexity", 0.0),
                        pattern_features.get("symbolic_depth", 0),
                    ]
                )

                # Calculate cosine similarity
                similarity = self._cosine_similarity(feature_vector, pattern_vector)
                if similarity >= threshold:
                    similarities.append((pattern_id, similarity))

        # Sort by similarity (highest first)
        similarities.sort(key=lambda x: x[1], reverse=True)
        return similarities

    def _cosine_similarity(self, a: np.ndarray, b: np.ndarray) -> float:
        """Calculate cosine similarity between two vectors."""
        if np.linalg.norm(a) == 0 or np.linalg.norm(b) == 0:
            return 0.0
        return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))

    def add_pattern(
        self, pattern_id: str, features: PatternFeatures, metadata: Dict[str, Any]
    ):
        """Add a new pattern to the database."""
        with self._lock:
            self.patterns[pattern_id] = {
                "features": features.to_dict(),
                "vm_family": metadata.get("vm_family", "Unknown"),
                "complexity": metadata.get("complexity", "Unknown"),
                "handler_type": metadata.get("handler_type", "Unknown"),
                "description": metadata.get("description", ""),
                "added_timestamp": datetime.now().isoformat(),
            }
            self.save_database()


class PatternClassifier:
    """
    Unified pattern classifier for VM bytecode analysis.

    This classifier consolidates multiple classification approaches:
    1. Similarity-based matching using pattern database
    2. Machine learning models (PyTorch/scikit-learn)
    3. Rule-based classification as fallback
    """

    def __init__(self, config: Optional[VMDragonSlayerConfig] = None):
        self.config = config or VMDragonSlayerConfig()
        self.feature_extractor = FeatureExtractor()
        self.pattern_database = PatternDatabase(
            self.config.pattern_database_path or "data/pattern_database.json"
        )

        # Initialize ML models if available
        self._ml_model = None
        self._sklearn_model = None
        self._sklearn_scaler = None

        if TORCH_AVAILABLE and self.config.use_pytorch:
            self._initialize_torch_model()

        if SKLEARN_AVAILABLE and self.config.use_sklearn:
            self._initialize_sklearn_model()

        logger.info(
            f"Initialized PatternClassifier with PyTorch={TORCH_AVAILABLE and self.config.use_pytorch}, "
            f"sklearn={SKLEARN_AVAILABLE and self.config.use_sklearn}"
        )

    def _initialize_torch_model(self):
        """Initialize PyTorch model if available."""
        try:
            # This would be replaced with actual model loading
            # For now, we'll create a placeholder
            logger.info(
                "PyTorch model initialization placeholder - would load actual model"
            )
            self._ml_model = None  # Placeholder
        except Exception as e:
            logger.error(f"Failed to initialize PyTorch model: {e}")
            self._ml_model = None

    def _initialize_sklearn_model(self):
        """Initialize scikit-learn model."""
        try:
            self._sklearn_model = RandomForestClassifier(
                n_estimators=100, random_state=42, n_jobs=1
            )
            self._sklearn_scaler = StandardScaler()
            logger.info("Initialized sklearn RandomForest model")
        except Exception as e:
            logger.error(f"Failed to initialize sklearn model: {e}")
            self._sklearn_model = None
            self._sklearn_scaler = None

    def classify_pattern(
        self,
        bytecode: bytes,
        taint_info: Optional[Dict] = None,
        symbolic_info: Optional[Dict] = None,
        use_similarity_search: bool = True,
    ) -> ClassificationResult:
        """
        Classify VM pattern using multiple approaches.

        Args:
            bytecode: The bytecode to classify
            taint_info: Optional taint tracking information
            symbolic_info: Optional symbolic execution information
            use_similarity_search: Whether to use similarity search first

        Returns:
            ClassificationResult with pattern type and metadata
        """
        if not bytecode:
            raise PatternAnalysisError("Empty bytecode provided for classification")

        # Extract features
        features = self.feature_extractor.extract_from_bytecode(
            bytecode, taint_info, symbolic_info
        )

        # Try similarity search first if enabled
        if use_similarity_search:
            result = self._classify_with_similarity(features)
            if result and result.confidence > 0.8:
                return result

        # Try ML models
        if self._ml_model:
            result = self._classify_with_pytorch(features)
            if result and result.confidence > 0.7:
                return result

        if self._sklearn_model:
            result = self._classify_with_sklearn(features)
            if result and result.confidence > 0.6:
                return result

        # Fallback to rule-based classification
        return self._classify_with_rules(features)

    def _classify_with_similarity(
        self, features: PatternFeatures
    ) -> Optional[ClassificationResult]:
        """Classify using pattern database similarity."""
        try:
            similar_patterns = self.pattern_database.get_similar_patterns(
                features, threshold=0.7
            )
            if not similar_patterns:
                return None

            pattern_id, similarity = similar_patterns[0]
            pattern_info = self.pattern_database.patterns[pattern_id]

            return ClassificationResult(
                pattern_type=pattern_id,
                confidence=similarity,
                vm_family=pattern_info.get("vm_family", "Unknown"),
                complexity=pattern_info.get("complexity", "Unknown"),
                handler_type=pattern_info.get("handler_type", "Unknown"),
                method="similarity",
                features=features,
                timestamp=datetime.now(),
            )
        except Exception as e:
            logger.error(f"Similarity classification failed: {e}")
            return None

    def _classify_with_pytorch(
        self, features: PatternFeatures
    ) -> Optional[ClassificationResult]:
        """Classify using PyTorch model."""
        try:
            # Placeholder for PyTorch classification
            # In real implementation, this would use a trained model
            logger.debug("PyTorch classification not implemented - using fallback")
            return None
        except Exception as e:
            logger.error(f"PyTorch classification failed: {e}")
            return None

    def _classify_with_sklearn(
        self, features: PatternFeatures
    ) -> Optional[ClassificationResult]:
        """Classify using scikit-learn model."""
        try:
            if not self._sklearn_model or not self._sklearn_scaler:
                return None

            # This would require a trained model
            # For now, return None to use rule-based fallback
            logger.debug(
                "Sklearn classification requires trained model - using fallback"
            )
            return None
        except Exception as e:
            logger.error(f"Sklearn classification failed: {e}")
            return None

    def _classify_with_rules(self, features: PatternFeatures) -> ClassificationResult:
        """Rule-based classification as fallback."""
        # Simple rule-based classification
        if features.arithmetic_operations > features.logical_operations:
            if features.arithmetic_operations >= 3:
                pattern_type = "VM_ADD"
                handler_type = "Arithmetic"
                complexity = (
                    "Medium" if features.control_flow_complexity > 2.0 else "Simple"
                )
            else:
                pattern_type = "VM_BASIC_ARITH"
                handler_type = "Arithmetic"
                complexity = "Simple"
        elif features.logical_operations > 0:
            pattern_type = "VM_XOR"
            handler_type = "Logical"
            complexity = "Simple"
        elif features.memory_operations > features.stack_operations:
            pattern_type = "VM_LOAD"
            handler_type = "Memory"
            complexity = "Medium"
        elif features.stack_operations > 0:
            pattern_type = "VM_STACK"
            handler_type = "Stack"
            complexity = "Simple"
        else:
            pattern_type = "VM_UNKNOWN"
            handler_type = "Unknown"
            complexity = "Unknown"

        # Calculate confidence based on feature clarity
        confidence = 0.5
        if features.instruction_count > 0:
            confidence += 0.1
        if features.unique_opcodes > 2:
            confidence += 0.1
        if features.control_flow_complexity > 1.0:
            confidence += 0.1

        confidence = min(confidence, 0.8)  # Cap rule-based confidence

        return ClassificationResult(
            pattern_type=pattern_type,
            confidence=confidence,
            vm_family="Generic",
            complexity=complexity,
            handler_type=handler_type,
            method="rules",
            features=features,
            timestamp=datetime.now(),
        )

    async def classify_pattern_async(
        self,
        bytecode: bytes,
        taint_info: Optional[Dict] = None,
        symbolic_info: Optional[Dict] = None,
    ) -> ClassificationResult:
        """Async version of pattern classification."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(
            None, self.classify_pattern, bytecode, taint_info, symbolic_info
        )

    def train_model(
        self, training_data: List[Tuple[bytes, str]], validation_split: float = 0.2
    ) -> Dict[str, float]:
        """
        Train the ML models on provided training data.

        Args:
            training_data: List of (bytecode, pattern_type) tuples
            validation_split: Fraction of data to use for validation

        Returns:
            Training metrics dictionary
        """
        if not training_data:
            raise MLError("No training data provided")

        logger.info(f"Training classifier on {len(training_data)} samples")

        # Extract features from training data
        features_list = []
        labels = []

        for bytecode, label in training_data:
            features = self.feature_extractor.extract_from_bytecode(bytecode)
            features_list.append(features.to_vector())
            labels.append(label)

        X = np.array(features_list)
        y = np.array(labels)

        # Split data
        split_idx = int(len(X) * (1 - validation_split))
        X_train, X_val = X[:split_idx], X[split_idx:]
        y_train, y_val = y[:split_idx], y[split_idx:]

        metrics = {}

        # Train sklearn model if available
        if SKLEARN_AVAILABLE and self._sklearn_model and self._sklearn_scaler:
            try:
                X_train_scaled = self._sklearn_scaler.fit_transform(X_train)
                X_val_scaled = self._sklearn_scaler.transform(X_val)

                self._sklearn_model.fit(X_train_scaled, y_train)

                # Evaluate
                y_pred = self._sklearn_model.predict(X_val_scaled)
                accuracy = accuracy_score(y_val, y_pred)
                metrics["sklearn_accuracy"] = accuracy

                logger.info(f"Sklearn model trained with accuracy: {accuracy:.3f}")
            except Exception as e:
                logger.error(f"Sklearn training failed: {e}")
                metrics["sklearn_error"] = str(e)

        # Add patterns to database
        for bytecode, label in training_data:
            features = self.feature_extractor.extract_from_bytecode(bytecode)
            # Use SHA256 for ID generation (avoid insecure md5)
            pattern_id = f"{label}_{hashlib.sha256(bytecode).hexdigest()[:8]}"

            metadata = {
                "vm_family": "Training",
                "complexity": "Unknown",
                "handler_type": "Unknown",
                "description": f"Training pattern for {label}",
            }

            self.pattern_database.add_pattern(pattern_id, features, metadata)

        metrics["patterns_added_to_db"] = len(training_data)
        return metrics

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        return {
            "pytorch_available": TORCH_AVAILABLE,
            "sklearn_available": SKLEARN_AVAILABLE,
            "pytorch_model_loaded": self._ml_model is not None,
            "sklearn_model_loaded": self._sklearn_model is not None,
            "pattern_database_size": len(self.pattern_database.patterns),
            "config": {
                "use_pytorch": self.config.use_pytorch,
                "use_sklearn": self.config.use_sklearn,
                "pattern_database_path": self.config.pattern_database_path,
            },
        }
