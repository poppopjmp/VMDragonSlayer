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
=================

Unified pattern classification system for VM bytecode analysis.

This module consolidates pattern classification functionality and provides
a clean interface to both rule-based and ML-based pattern classification.
"""

import logging
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

# Optional ML dependencies with graceful fallback
try:
    import numpy as np

    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import sklearn
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, classification_report
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler

    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

from ...core.config import VMDragonSlayerConfig
from ...core.exceptions import (
    PatternAnalysisError,
)
from .database import PatternDatabase
from .recognizer import FeatureExtractor, PatternMatch, PatternRecognizer

logger = logging.getLogger(__name__)


class ClassificationMethod(Enum):
    """Classification methods available"""

    RULE_BASED = "rule_based"
    SIMILARITY = "similarity"
    ML_SKLEARN = "ml_sklearn"
    HYBRID = "hybrid"
    AUTO = "auto"


class ClassificationConfidence(Enum):
    """Classification confidence levels"""

    VERY_HIGH = 0.95
    HIGH = 0.80
    MEDIUM = 0.65
    LOW = 0.50
    VERY_LOW = 0.35


@dataclass
class ClassificationResult:
    """Result of pattern classification"""

    predicted_class: str
    confidence: float
    method: ClassificationMethod
    features: Optional[List[float]] = None
    pattern_matches: List[PatternMatch] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    execution_time: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "predicted_class": self.predicted_class,
            "confidence": self.confidence,
            "method": self.method.value,
            "features": self.features,
            "pattern_matches": [match.to_dict() for match in self.pattern_matches],
            "metadata": self.metadata,
            "execution_time": self.execution_time,
        }


class SimilarityClassifier:
    """Similarity-based pattern classifier"""

    def __init__(self, pattern_database: PatternDatabase):
        self.pattern_database = pattern_database
        self.similarity_cache = {}

    def classify(
        self, bytecode_sequence: List[int], context: Optional[Dict] = None
    ) -> ClassificationResult:
        """Classify using similarity matching

        Args:
            bytecode_sequence: Sequence to classify
            context: Optional context information

        Returns:
            Classification result
        """
        context = context or {}

        # Convert to bytes for pattern matching
        bytecode_bytes = bytes(bytecode_sequence)

        # Find pattern matches
        matches = []
        try:
            import asyncio

            if asyncio.iscoroutinefunction(self.pattern_database.match_patterns):
                # Handle async case - in practice would use proper async handling
                loop = asyncio.get_event_loop()
                matches = loop.run_until_complete(
                    self.pattern_database.match_patterns(bytecode_bytes, threshold=0.5)
                )
            else:
                matches = self.pattern_database.match_patterns(
                    bytecode_bytes, threshold=0.5
                )
        except Exception as e:
            logger.debug("Pattern matching failed: %s", e)
            matches = []

        if not matches:
            return ClassificationResult(
                predicted_class="unknown",
                confidence=0.1,
                method=ClassificationMethod.SIMILARITY,
                metadata={"reason": "no_pattern_matches"},
            )

        # Get best match
        best_match = max(matches, key=lambda m: m.confidence)

        # Determine class based on pattern type
        pattern_id = best_match.pattern_id
        pattern = self.pattern_database.get_pattern(pattern_id)

        if pattern:
            predicted_class = pattern.pattern_type.value
            confidence = best_match.confidence * 0.8  # Discount for similarity method
        else:
            predicted_class = "unknown"
            confidence = 0.2

        return ClassificationResult(
            predicted_class=predicted_class,
            confidence=confidence,
            method=ClassificationMethod.SIMILARITY,
            pattern_matches=[self._convert_match(best_match)],
            metadata={"best_pattern": pattern_id, "total_matches": len(matches)},
        )

    def _convert_match(self, db_match) -> PatternMatch:
        """Convert database match to PatternMatch"""
        return PatternMatch(
            pattern_name=db_match.pattern_id,
            confidence=db_match.confidence,
            pattern_type=db_match.context.get("pattern_type", "unknown"),
            matched_sequence=[],  # Would need to extract from location/length
            start_offset=db_match.location,
            end_offset=db_match.location + db_match.length,
            metadata=db_match.context,
        )


class MLClassifier:
    """Machine learning pattern classifier"""

    def __init__(self, config: VMDragonSlayerConfig):
        self.config = config
        self.model = None
        self.scaler = None
        self.feature_extractor = FeatureExtractor()
        self.training_data = []
        self.training_labels = []
        self.is_trained = False
        self.class_names = []

        if not HAS_SKLEARN:
            logger.warning("scikit-learn not available, ML classification disabled")

    def add_training_example(
        self, bytecode_sequence: List[int], label: str, context: Optional[Dict] = None
    ):
        """Add training example

        Args:
            bytecode_sequence: Training sequence
            label: Class label
            context: Optional context
        """
        if not HAS_SKLEARN:
            return

        features = self.feature_extractor.extract_features(bytecode_sequence, context)
        self.training_data.append(features)
        self.training_labels.append(label)

        if label not in self.class_names:
            self.class_names.append(label)

        logger.debug("Added training example for class: %s", label)

    def train(self) -> bool:
        """Train the ML model

        Returns:
            True if training successful, False otherwise
        """
        if not HAS_SKLEARN or not HAS_NUMPY:
            logger.warning("ML dependencies not available for training")
            return False

        if len(self.training_data) < 10:
            logger.warning(
                "Insufficient training data (%d examples)", len(self.training_data)
            )
            return False

        try:
            # Convert to numpy arrays
            X = np.array(self.training_data)
            y = np.array(self.training_labels)

            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42
            )

            # Scale features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)

            # Train model
            self.model = RandomForestClassifier(
                n_estimators=100, random_state=42, max_depth=10
            )
            self.model.fit(X_train_scaled, y_train)

            # Evaluate
            y_pred = self.model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)

            self.is_trained = True

            logger.info("ML model trained with accuracy: %.3f", accuracy)
            logger.debug(
                "Training data: %d examples, %d classes",
                len(self.training_data),
                len(self.class_names),
            )

            return True

        except Exception as e:
            logger.error("ML training failed: %s", e)
            return False

    def classify(
        self, bytecode_sequence: List[int], context: Optional[Dict] = None
    ) -> ClassificationResult:
        """Classify using ML model

        Args:
            bytecode_sequence: Sequence to classify
            context: Optional context

        Returns:
            Classification result
        """
        if not self.is_trained or not HAS_SKLEARN or not HAS_NUMPY:
            return ClassificationResult(
                predicted_class="unknown",
                confidence=0.1,
                method=ClassificationMethod.ML_SKLEARN,
                metadata={"reason": "model_not_trained"},
            )

        try:
            # Extract features
            features = self.feature_extractor.extract_features(
                bytecode_sequence, context
            )
            X = np.array([features])

            # Scale features
            X_scaled = self.scaler.transform(X)

            # Predict
            predictions = self.model.predict(X_scaled)
            probabilities = self.model.predict_proba(X_scaled)

            predicted_class = predictions[0]
            confidence = float(np.max(probabilities))

            return ClassificationResult(
                predicted_class=predicted_class,
                confidence=confidence,
                method=ClassificationMethod.ML_SKLEARN,
                features=features,
                metadata={
                    "probabilities": dict(zip(self.model.classes_, probabilities[0])),
                    "feature_count": len(features),
                },
            )

        except Exception as e:
            logger.error("ML classification failed: %s", e)
            return ClassificationResult(
                predicted_class="unknown",
                confidence=0.1,
                method=ClassificationMethod.ML_SKLEARN,
                metadata={"error": str(e)},
            )


class RuleBasedClassifier:
    """Rule-based pattern classifier"""

    def __init__(self, pattern_recognizer: PatternRecognizer):
        self.pattern_recognizer = pattern_recognizer

    async def classify(
        self, bytecode_sequence: List[int], context: Optional[Dict] = None
    ) -> ClassificationResult:
        """Classify using rule-based patterns

        Args:
            bytecode_sequence: Sequence to classify
            context: Optional context

        Returns:
            Classification result
        """
        try:
            # Get pattern matches
            matches = await self.pattern_recognizer.recognize_patterns(
                bytecode_sequence, context
            )

            if not matches:
                return ClassificationResult(
                    predicted_class="unknown",
                    confidence=0.2,
                    method=ClassificationMethod.RULE_BASED,
                    metadata={"reason": "no_pattern_matches"},
                )

            # Get best match
            best_match = matches[0]  # Already sorted by confidence

            return ClassificationResult(
                predicted_class=best_match.pattern_type,
                confidence=best_match.confidence,
                method=ClassificationMethod.RULE_BASED,
                pattern_matches=matches[:5],  # Top 5 matches
                metadata={
                    "total_matches": len(matches),
                    "best_pattern": best_match.pattern_name,
                },
            )

        except Exception as e:
            logger.error("Rule-based classification failed: %s", e)
            return ClassificationResult(
                predicted_class="unknown",
                confidence=0.1,
                method=ClassificationMethod.RULE_BASED,
                metadata={"error": str(e)},
            )


class PatternClassifier:
    """Main pattern classification system"""

    def __init__(self, config: Optional[VMDragonSlayerConfig] = None):
        """Initialize pattern classifier

        Args:
            config: VMDragonSlayer configuration
        """
        self.config = config or VMDragonSlayerConfig()

        # Initialize components
        self.pattern_database = PatternDatabase(config)
        self.pattern_recognizer = PatternRecognizer(config)
        self.similarity_classifier = SimilarityClassifier(self.pattern_database)
        self.ml_classifier = MLClassifier(config)
        self.rule_classifier = RuleBasedClassifier(self.pattern_recognizer)

        # Classification cache
        self.classification_cache = {}
        self._cache_lock = threading.Lock()

        # Default method selection
        self.default_method = ClassificationMethod.AUTO

        logger.info("Pattern classifier initialized")

    async def classify(
        self,
        bytecode_sequence: List[int],
        context: Optional[Dict] = None,
        method: Optional[ClassificationMethod] = None,
    ) -> ClassificationResult:
        """Classify bytecode sequence

        Args:
            bytecode_sequence: Sequence to classify
            context: Optional context information
            method: Classification method to use

        Returns:
            Classification result
        """
        import time

        start_time = time.time()

        context = context or {}
        method = method or self.default_method

        # Check cache
        cache_key = (tuple(bytecode_sequence), tuple(sorted(context.items())), method)
        with self._cache_lock:
            if cache_key in self.classification_cache:
                result = self.classification_cache[cache_key]
                result.execution_time = time.time() - start_time
                return result

        try:
            if method == ClassificationMethod.AUTO:
                result = await self._auto_classify(bytecode_sequence, context)
            elif method == ClassificationMethod.RULE_BASED:
                result = await self.rule_classifier.classify(bytecode_sequence, context)
            elif method == ClassificationMethod.SIMILARITY:
                result = self.similarity_classifier.classify(bytecode_sequence, context)
            elif method == ClassificationMethod.ML_SKLEARN:
                result = self.ml_classifier.classify(bytecode_sequence, context)
            elif method == ClassificationMethod.HYBRID:
                result = await self._hybrid_classify(bytecode_sequence, context)
            else:
                raise PatternAnalysisError(f"Unknown classification method: {method}")

            result.execution_time = time.time() - start_time

            # Cache result
            with self._cache_lock:
                self.classification_cache[cache_key] = result

            return result

        except Exception as e:
            logger.error("Classification failed: %s", e)
            return ClassificationResult(
                predicted_class="error",
                confidence=0.0,
                method=method,
                metadata={"error": str(e)},
                execution_time=time.time() - start_time,
            )

    async def _auto_classify(
        self, bytecode_sequence: List[int], context: Dict
    ) -> ClassificationResult:
        """Automatically select best classification method"""

        # Try rule-based first (fastest and most accurate for known patterns)
        rule_result = await self.rule_classifier.classify(bytecode_sequence, context)
        if rule_result.confidence >= 0.8:
            return rule_result

        # Try similarity if rule-based has low confidence
        similarity_result = self.similarity_classifier.classify(
            bytecode_sequence, context
        )
        if similarity_result.confidence >= 0.7:
            return similarity_result

        # Try ML if available and previous methods failed
        if self.ml_classifier.is_trained:
            ml_result = self.ml_classifier.classify(bytecode_sequence, context)
            if ml_result.confidence >= 0.6:
                return ml_result

        # Return best result
        results = [rule_result, similarity_result]
        if self.ml_classifier.is_trained:
            ml_result = self.ml_classifier.classify(bytecode_sequence, context)
            results.append(ml_result)

        best_result = max(results, key=lambda r: r.confidence)
        best_result.method = ClassificationMethod.AUTO
        return best_result

    async def _hybrid_classify(
        self, bytecode_sequence: List[int], context: Dict
    ) -> ClassificationResult:
        """Hybrid classification using multiple methods"""

        # Run all available methods
        methods_results = []

        # Rule-based
        rule_result = await self.rule_classifier.classify(bytecode_sequence, context)
        methods_results.append(("rule", rule_result))

        # Similarity
        similarity_result = self.similarity_classifier.classify(
            bytecode_sequence, context
        )
        methods_results.append(("similarity", similarity_result))

        # ML if available
        if self.ml_classifier.is_trained:
            ml_result = self.ml_classifier.classify(bytecode_sequence, context)
            methods_results.append(("ml", ml_result))

        # Weighted voting
        class_votes = {}
        total_weight = 0

        for method_name, result in methods_results:
            weight = self._get_method_weight(method_name, result.confidence)
            predicted_class = result.predicted_class

            if predicted_class not in class_votes:
                class_votes[predicted_class] = 0

            class_votes[predicted_class] += weight * result.confidence
            total_weight += weight

        if not class_votes:
            return ClassificationResult(
                predicted_class="unknown",
                confidence=0.1,
                method=ClassificationMethod.HYBRID,
                metadata={"reason": "no_valid_predictions"},
            )

        # Get winning class
        winning_class = max(class_votes.keys(), key=lambda c: class_votes[c])
        confidence = (
            class_votes[winning_class] / total_weight if total_weight > 0 else 0.0
        )

        # Collect all pattern matches
        all_matches = []
        for _, result in methods_results:
            all_matches.extend(result.pattern_matches)

        return ClassificationResult(
            predicted_class=winning_class,
            confidence=min(confidence, 1.0),
            method=ClassificationMethod.HYBRID,
            pattern_matches=all_matches[:10],  # Top 10 matches
            metadata={
                "method_results": {
                    method_name: {
                        "class": result.predicted_class,
                        "confidence": result.confidence,
                    }
                    for method_name, result in methods_results
                },
                "class_votes": class_votes,
            },
        )

    def _get_method_weight(self, method_name: str, confidence: float) -> float:
        """Get weight for method in hybrid classification"""
        base_weights = {
            "rule": 1.0,  # Highest weight for rule-based
            "similarity": 0.8,  # Medium weight for similarity
            "ml": 0.6,  # Lower weight for ML (less reliable)
        }

        base_weight = base_weights.get(method_name, 0.5)

        # Boost weight for high confidence results
        confidence_boost = 1.0 + (confidence - 0.5) * 0.5

        return base_weight * confidence_boost

    def add_training_data(
        self, bytecode_sequence: List[int], label: str, context: Optional[Dict] = None
    ):
        """Add training data for ML classifier

        Args:
            bytecode_sequence: Training sequence
            label: Class label
            context: Optional context
        """
        self.ml_classifier.add_training_example(bytecode_sequence, label, context)

    def train_ml_model(self) -> bool:
        """Train the ML model

        Returns:
            True if training successful
        """
        return self.ml_classifier.train()

    def clear_cache(self):
        """Clear classification cache"""
        with self._cache_lock:
            self.classification_cache.clear()

        self.pattern_recognizer.clear_cache()
        logger.debug("Pattern classification cache cleared")

    def get_statistics(self) -> Dict[str, Any]:
        """Get classifier statistics

        Returns:
            Dictionary of statistics
        """
        return {
            "pattern_database_stats": self.pattern_database.get_statistics(),
            "pattern_recognizer_stats": self.pattern_recognizer.get_statistics(),
            "ml_model_trained": self.ml_classifier.is_trained,
            "ml_training_examples": len(self.ml_classifier.training_data),
            "cache_size": len(self.classification_cache),
            "default_method": self.default_method.value,
            "available_methods": [method.value for method in ClassificationMethod],
        }
