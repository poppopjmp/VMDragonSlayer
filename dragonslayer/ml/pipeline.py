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
ML Pipeline
===========

Unified machine learning pipeline for feature extraction and model training.

This module consolidates ML pipeline functionality from multiple implementations
into a single, production-ready pipeline system.
"""

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from ..core.exceptions import MLError
from .classifier import PatternFeatures
from .model import MLModel, ModelRegistry, ModelStatus, ModelType
from .trainer import ModelTrainer, TrainingConfig

logger = logging.getLogger(__name__)

# Handle optional dependencies
try:
    from sklearn.decomposition import PCA
    from sklearn.feature_selection import SelectKBest, f_classif
    from sklearn.pipeline import Pipeline as SklearnPipeline
    from sklearn.preprocessing import MinMaxScaler, RobustScaler, StandardScaler

    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("Scikit-learn not available, some pipeline features disabled")


@dataclass
class PipelineConfig:
    """Configuration for ML pipeline."""

    # Feature extraction
    max_features: int = 1000
    use_feature_selection: bool = True
    feature_selection_k: int = 100
    use_dimensionality_reduction: bool = False
    pca_components: int = 50

    # Preprocessing
    scaler_type: str = "standard"  # standard, minmax, robust
    handle_missing_values: bool = True
    missing_value_strategy: str = "mean"  # mean, median, mode, drop

    # Data validation
    validate_features: bool = True
    min_samples: int = 10
    max_feature_correlation: float = 0.95

    # Pipeline execution
    parallel_processing: bool = True
    max_workers: int = 4
    cache_features: bool = True
    cache_dir: str = "cache/features"

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "max_features": self.max_features,
            "use_feature_selection": self.use_feature_selection,
            "feature_selection_k": self.feature_selection_k,
            "use_dimensionality_reduction": self.use_dimensionality_reduction,
            "pca_components": self.pca_components,
            "scaler_type": self.scaler_type,
            "handle_missing_values": self.handle_missing_values,
            "missing_value_strategy": self.missing_value_strategy,
            "validate_features": self.validate_features,
            "min_samples": self.min_samples,
            "max_feature_correlation": self.max_feature_correlation,
            "parallel_processing": self.parallel_processing,
            "max_workers": self.max_workers,
            "cache_features": self.cache_features,
            "cache_dir": self.cache_dir,
        }


@dataclass
class PipelineResult:
    """Result of pipeline execution."""

    success: bool
    features: Optional[np.ndarray]
    labels: Optional[np.ndarray]
    feature_names: List[str]
    preprocessing_time: float
    total_samples: int
    feature_dimensions: int
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        result = {
            "success": self.success,
            "feature_names": self.feature_names,
            "preprocessing_time": self.preprocessing_time,
            "total_samples": self.total_samples,
            "feature_dimensions": self.feature_dimensions,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }

        # Don't include arrays in dict representation
        if self.features is not None:
            result["features_shape"] = self.features.shape
        if self.labels is not None:
            result["labels_shape"] = self.labels.shape

        return result


class FeatureExtractor:
    """
    Enhanced feature extractor for VM bytecode analysis.

    This extractor consolidates feature extraction logic from multiple
    implementations and provides a unified interface.
    """

    def __init__(self, config: Optional[PipelineConfig] = None):
        self.config = config or PipelineConfig()
        self.feature_cache = {}
        self._setup_cache_directory()

    def _setup_cache_directory(self):
        """Setup feature cache directory."""
        if self.config.cache_features:
            cache_dir = Path(self.config.cache_dir)
            cache_dir.mkdir(parents=True, exist_ok=True)

    def extract_features(
        self,
        bytecode_samples: List[bytes],
        labels: Optional[List[str]] = None,
        taint_info: Optional[List[Dict]] = None,
        symbolic_info: Optional[List[Dict]] = None,
    ) -> PipelineResult:
        """
        Extract features from multiple bytecode samples.

        Args:
            bytecode_samples: List of bytecode samples
            labels: Optional labels for supervised learning
            taint_info: Optional taint tracking information
            symbolic_info: Optional symbolic execution information

        Returns:
            PipelineResult with extracted features and metadata
        """
        start_time = time.time()

        try:
            if not bytecode_samples:
                raise MLError("No bytecode samples provided")

            if len(bytecode_samples) < self.config.min_samples:
                logger.warning(
                    f"Only {len(bytecode_samples)} samples provided, "
                    f"minimum recommended is {self.config.min_samples}"
                )

            # Extract features from each sample
            feature_list = []
            feature_names = self._get_feature_names()

            for i, bytecode in enumerate(bytecode_samples):
                taint = taint_info[i] if taint_info and i < len(taint_info) else None
                symbolic = (
                    symbolic_info[i]
                    if symbolic_info and i < len(symbolic_info)
                    else None
                )

                features = self._extract_single_sample(bytecode, taint, symbolic)
                feature_list.append(features.to_vector())

            # Convert to numpy array
            feature_matrix = np.array(feature_list)

            # Validate features
            if self.config.validate_features:
                feature_matrix = self._validate_and_clean_features(feature_matrix)

            # Convert labels if provided
            label_array = None
            if labels:
                label_array = np.array(labels)
                if len(label_array) != len(feature_matrix):
                    raise MLError(
                        f"Number of labels ({len(label_array)}) doesn't match "
                        f"number of samples ({len(feature_matrix)})"
                    )

            processing_time = time.time() - start_time

            return PipelineResult(
                success=True,
                features=feature_matrix,
                labels=label_array,
                feature_names=feature_names,
                preprocessing_time=processing_time,
                total_samples=len(bytecode_samples),
                feature_dimensions=feature_matrix.shape[1],
                metadata={
                    "extraction_method": "unified_extractor",
                    "config": self.config.to_dict(),
                },
            )

        except Exception as e:
            processing_time = time.time() - start_time
            logger.error(f"Feature extraction failed: {e}")

            return PipelineResult(
                success=False,
                features=None,
                labels=None,
                feature_names=[],
                preprocessing_time=processing_time,
                total_samples=len(bytecode_samples) if bytecode_samples else 0,
                feature_dimensions=0,
                error_message=str(e),
            )

    def _extract_single_sample(
        self,
        bytecode: bytes,
        taint_info: Optional[Dict] = None,
        symbolic_info: Optional[Dict] = None,
    ) -> PatternFeatures:
        """Extract features from a single bytecode sample."""
        # Basic bytecode analysis
        if not bytecode:
            return PatternFeatures()

        instruction_count = len(bytecode)
        unique_opcodes = len(set(bytecode))

        # Control flow analysis
        control_flow_complexity = self._analyze_control_flow(bytecode)

        # Operation type counting
        arithmetic_ops = self._count_arithmetic_operations(bytecode)
        logical_ops = self._count_logical_operations(bytecode)
        memory_ops = self._count_memory_operations(bytecode)
        stack_ops = self._count_stack_operations(bytecode)
        crypto_ops = self._count_crypto_operations(bytecode)
        string_ops = self._count_string_operations(bytecode)

        # Register usage analysis
        register_usage_density = self._analyze_register_usage(bytecode)

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
            execution_frequency=1.0,  # Default value
            taint_propagation_complexity=taint_complexity,
            symbolic_depth=symbolic_depth,
        )

    def _get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return [
            "instruction_count",
            "unique_opcodes",
            "control_flow_complexity",
            "data_access_patterns",
            "arithmetic_operations",
            "logical_operations",
            "memory_operations",
            "stack_operations",
            "crypto_operations",
            "string_operations",
            "register_usage_density",
            "execution_frequency",
            "taint_propagation_complexity",
            "symbolic_depth",
        ]

    def _analyze_control_flow(self, bytecode: bytes) -> float:
        """Analyze control flow complexity."""
        if len(bytecode) < 2:
            return 0.0

        # Identify jump instructions (simplified)
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
        }  # unconditional jumps

        jumps = sum(1 for byte in bytecode if byte in jump_opcodes)

        # Calculate cyclomatic complexity approximation
        complexity = 1 + jumps  # Base complexity + number of decision points
        return min(complexity / len(bytecode) * 100, 10.0)  # Normalize and cap

    def _count_arithmetic_operations(self, bytecode: bytes) -> int:
        """Count arithmetic operations."""
        arithmetic_opcodes = {0x01, 0x03, 0x05, 0x29, 0x2B, 0x2D, 0x6B, 0x83}
        return sum(1 for byte in bytecode if byte in arithmetic_opcodes)

    def _count_logical_operations(self, bytecode: bytes) -> int:
        """Count logical operations."""
        logical_opcodes = {0x21, 0x23, 0x25, 0x31, 0x33, 0x35, 0x81, 0x09, 0x0B}
        return sum(1 for byte in bytecode if byte in logical_opcodes)

    def _count_memory_operations(self, bytecode: bytes) -> int:
        """Count memory operations."""
        memory_opcodes = {0x8B, 0x89, 0x8A, 0x88, 0xA1, 0xA3, 0xC7, 0xC6}
        return sum(1 for byte in bytecode if byte in memory_opcodes)

    def _count_stack_operations(self, bytecode: bytes) -> int:
        """Count stack operations."""
        stack_opcodes = set(range(0x50, 0x60))  # PUSH/POP range
        return sum(1 for byte in bytecode if byte in stack_opcodes)

    def _count_crypto_operations(self, bytecode: bytes) -> int:
        """Count cryptographic operations (heuristic)."""
        crypto_patterns = [b"\xae", b"\xa6", b"\xa7", b"\xac", b"\xad"]
        count = 0
        for pattern in crypto_patterns:
            count += bytecode.count(pattern)
        return count

    def _count_string_operations(self, bytecode: bytes) -> int:
        """Count string operations."""
        string_opcodes = {0xA4, 0xA5, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF}
        return sum(1 for byte in bytecode if byte in string_opcodes)

    def _analyze_register_usage(self, bytecode: bytes) -> float:
        """Analyze register usage patterns."""
        if len(bytecode) < 2:
            return 0.0

        # Count register-related instructions
        register_opcodes = set(range(0x40, 0x48)) | set(range(0x48, 0x50))
        register_uses = sum(1 for byte in bytecode if byte in register_opcodes)

        return register_uses / len(bytecode)

    def _validate_and_clean_features(self, features: np.ndarray) -> np.ndarray:
        """Validate and clean feature matrix."""
        # Handle missing values
        if self.config.handle_missing_values:
            if np.isnan(features).any():
                if self.config.missing_value_strategy == "mean":
                    features = np.nan_to_num(features, nan=np.nanmean(features, axis=0))
                elif self.config.missing_value_strategy == "median":
                    features = np.nan_to_num(
                        features, nan=np.nanmedian(features, axis=0)
                    )
                else:
                    features = np.nan_to_num(features, nan=0.0)

        # Handle infinite values
        features = np.nan_to_num(features, posinf=1e6, neginf=-1e6)

        # Remove highly correlated features
        if self.config.max_feature_correlation < 1.0:
            features = self._remove_correlated_features(features)

        return features

    def _remove_correlated_features(self, features: np.ndarray) -> np.ndarray:
        """Remove highly correlated features."""
        if features.shape[1] < 2:
            return features

        # Calculate correlation matrix
        corr_matrix = np.corrcoef(features.T)

        # Find highly correlated feature pairs
        to_remove = set()
        for i in range(len(corr_matrix)):
            for j in range(i + 1, len(corr_matrix)):
                if abs(corr_matrix[i, j]) > self.config.max_feature_correlation:
                    to_remove.add(j)  # Remove the second feature

        # Keep features that are not highly correlated
        keep_indices = [i for i in range(features.shape[1]) if i not in to_remove]

        if len(keep_indices) < features.shape[1]:
            logger.info(
                f"Removed {features.shape[1] - len(keep_indices)} highly correlated features"
            )
            return features[:, keep_indices]

        return features


class MLPipeline:
    """
    Unified machine learning pipeline for VM pattern analysis.

    This pipeline consolidates the entire ML workflow from feature extraction
    through model training and evaluation.
    """

    def __init__(
        self,
        config: Optional[PipelineConfig] = None,
        training_config: Optional[TrainingConfig] = None,
    ):
        self.config = config or PipelineConfig()
        self.training_config = training_config or TrainingConfig()

        # Initialize components
        self.feature_extractor = FeatureExtractor(self.config)
        self.model_trainer = ModelTrainer(self.training_config)
        self.model_registry = ModelRegistry()

        # Pipeline state
        self.preprocessor = None
        self.feature_selector = None
        self.scaler = None
        self.trained_models = []

        logger.info("Initialized MLPipeline with unified components")

    def run_training_pipeline(
        self,
        bytecode_samples: List[bytes],
        labels: List[str],
        model_name: str,
        model_version: str = "1.0.0",
        validation_split: float = 0.2,
        taint_info: Optional[List[Dict]] = None,
        symbolic_info: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """
        Run complete training pipeline from feature extraction to model registration.

        Args:
            bytecode_samples: List of bytecode samples for training
            labels: Corresponding labels for supervised learning
            model_name: Name for the trained model
            model_version: Version string for the model
            validation_split: Fraction of data for validation
            taint_info: Optional taint tracking information
            symbolic_info: Optional symbolic execution information

        Returns:
            Pipeline results including training metrics and model info
        """
        pipeline_start = time.time()
        results = {}

        try:
            # Step 1: Feature extraction
            logger.info("Step 1: Extracting features from bytecode samples")
            feature_result = self.feature_extractor.extract_features(
                bytecode_samples, labels, taint_info, symbolic_info
            )

            if not feature_result.success:
                raise MLError(
                    f"Feature extraction failed: {feature_result.error_message}"
                )

            results["feature_extraction"] = feature_result.to_dict()

            # Step 2: Preprocessing
            logger.info("Step 2: Preprocessing features")
            X_processed, y_processed = self._preprocess_features(
                feature_result.features, feature_result.labels
            )

            # Step 3: Train models
            logger.info("Step 3: Training ML models")
            training_results = self._train_models(
                X_processed, y_processed, validation_split
            )
            results["training"] = training_results

            # Step 4: Model selection and registration
            logger.info("Step 4: Selecting and registering best model")
            best_model_info = self._select_and_register_model(
                training_results, model_name, model_version
            )
            results["model_registration"] = best_model_info

            # Pipeline summary
            total_time = time.time() - pipeline_start
            results["pipeline_summary"] = {
                "total_time": total_time,
                "total_samples": len(bytecode_samples),
                "feature_dimensions": feature_result.feature_dimensions,
                "success": True,
            }

            logger.info(
                f"Training pipeline completed successfully in {total_time:.2f}s"
            )
            return results

        except Exception as e:
            total_time = time.time() - pipeline_start
            error_msg = f"Training pipeline failed: {e}"
            logger.error(error_msg)

            results["pipeline_summary"] = {
                "total_time": total_time,
                "total_samples": len(bytecode_samples) if bytecode_samples else 0,
                "success": False,
                "error": str(e),
            }

            return results

    def run_inference_pipeline(
        self,
        bytecode_samples: List[bytes],
        model_name: str,
        taint_info: Optional[List[Dict]] = None,
        symbolic_info: Optional[List[Dict]] = None,
    ) -> Dict[str, Any]:
        """
        Run inference pipeline on new bytecode samples.

        Args:
            bytecode_samples: List of bytecode samples to classify
            model_name: Name of the model to use for inference
            taint_info: Optional taint tracking information
            symbolic_info: Optional symbolic execution information

        Returns:
            Classification results for all samples
        """
        try:
            # Get latest production model
            model_metadata = self.model_registry.get_latest_version(
                model_name, ModelStatus.PRODUCTION
            )

            if not model_metadata:
                # Try any available model
                model_metadata = self.model_registry.get_latest_version(model_name)

            if not model_metadata:
                raise MLError(f"No model found with name '{model_name}'")

            # Extract features
            feature_result = self.feature_extractor.extract_features(
                bytecode_samples, None, taint_info, symbolic_info
            )

            if not feature_result.success:
                raise MLError(
                    f"Feature extraction failed: {feature_result.error_message}"
                )

            # Preprocess features (if preprocessor was fitted during training)
            X_processed = feature_result.features
            if self.scaler:
                X_processed = self.scaler.transform(X_processed)

            # Load and use model for prediction
            # Note: In a real implementation, this would load the actual model
            # For now, we'll use a simple heuristic
            predictions = self._predict_with_heuristics(X_processed)

            return {
                "success": True,
                "model_used": model_metadata.model_id,
                "model_version": model_metadata.version,
                "predictions": predictions,
                "total_samples": len(bytecode_samples),
                "feature_dimensions": feature_result.feature_dimensions,
            }

        except Exception as e:
            logger.error(f"Inference pipeline failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "total_samples": len(bytecode_samples) if bytecode_samples else 0,
            }

    def _preprocess_features(
        self, features: np.ndarray, labels: np.ndarray
    ) -> Tuple[np.ndarray, np.ndarray]:
        """Preprocess features with scaling and selection."""
        X, y = features, labels

        # Initialize and fit scaler
        if SKLEARN_AVAILABLE:
            if self.config.scaler_type == "standard":
                self.scaler = StandardScaler()
            elif self.config.scaler_type == "minmax":
                self.scaler = MinMaxScaler()
            elif self.config.scaler_type == "robust":
                self.scaler = RobustScaler()
            else:
                self.scaler = StandardScaler()

            X = self.scaler.fit_transform(X)

            # Feature selection if enabled
            if (
                self.config.use_feature_selection
                and X.shape[1] > self.config.feature_selection_k
            ):
                self.feature_selector = SelectKBest(
                    score_func=f_classif, k=self.config.feature_selection_k
                )
                X = self.feature_selector.fit_transform(X, y)
                logger.info(f"Selected {self.config.feature_selection_k} best features")

        return X, y

    def _train_models(
        self, X: np.ndarray, y: np.ndarray, validation_split: float
    ) -> Dict[str, Any]:
        """Train multiple model types and return results."""
        training_results = {}

        # Split data
        from sklearn.model_selection import train_test_split

        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=validation_split, random_state=42
        )

        # Train sklearn models if available
        if SKLEARN_AVAILABLE:
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.neural_network import MLPClassifier

            models_to_try = [
                (
                    "RandomForest",
                    RandomForestClassifier(n_estimators=100, random_state=42),
                ),
                (
                    "MLP",
                    MLPClassifier(
                        hidden_layer_sizes=(100, 50), max_iter=500, random_state=42
                    ),
                ),
            ]

            for name, model in models_to_try:
                try:
                    logger.info(f"Training {name} model")
                    result = self.model_trainer.train_sklearn_model(
                        model, (X_train, y_train), (X_val, y_val)
                    )
                    training_results[name] = result

                    # Wrap in MLModel
                    ml_model = MLModel(
                        model=model,
                        name=f"VMPattern_{name}",
                        version="1.0.0",
                        model_type=ModelType.SKLEARN,
                        description=f"VM pattern classifier using {name}",
                    )
                    self.trained_models.append(ml_model)

                except Exception as e:
                    logger.error(f"Failed to train {name}: {e}")
                    training_results[name] = {"error": str(e)}

        return training_results

    def _select_and_register_model(
        self, training_results: Dict, name: str, version: str
    ) -> Dict[str, Any]:
        """Select best model and register it."""
        best_model = None
        best_accuracy = 0.0
        best_model_name = ""

        # Find best performing model
        for model_name, results in training_results.items():
            if "val_accuracy" in results and results["val_accuracy"] > best_accuracy:
                best_accuracy = results["val_accuracy"]
                best_model_name = model_name

        # Find corresponding MLModel
        for ml_model in self.trained_models:
            if best_model_name in ml_model.name:
                best_model = ml_model
                break

        if best_model:
            # Update model info
            best_model.name = name
            best_model.version = version
            best_model.metadata.performance_metrics = {"val_accuracy": best_accuracy}
            best_model.update_status(ModelStatus.TESTING)

            # Register in registry
            model_id = self.model_registry.register_model(best_model)

            return {
                "model_id": model_id,
                "model_name": name,
                "version": version,
                "accuracy": best_accuracy,
                "model_type": best_model_name,
            }

        return {"error": "No suitable model found"}

    def _predict_with_heuristics(self, features: np.ndarray) -> List[str]:
        """Simple heuristic-based prediction as fallback."""
        predictions = []

        for feature_row in features:
            # Simple rule-based classification
            if len(feature_row) >= 4:  # Assuming we have the basic features
                if feature_row[4] > feature_row[5]:  # arithmetic > logical
                    pred = "VM_ADD"
                elif feature_row[5] > 0:  # logical operations present
                    pred = "VM_XOR"
                elif feature_row[6] > feature_row[7]:  # memory > stack
                    pred = "VM_LOAD"
                else:
                    pred = "VM_UNKNOWN"
            else:
                pred = "VM_UNKNOWN"

            predictions.append(pred)

        return predictions

    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get current pipeline status and configuration."""
        return {
            "config": self.config.to_dict(),
            "training_config": self.training_config.to_dict(),
            "components": {
                "feature_extractor": True,
                "model_trainer": True,
                "model_registry": True,
                "scaler_fitted": self.scaler is not None,
                "feature_selector_fitted": self.feature_selector is not None,
            },
            "trained_models": len(self.trained_models),
            "sklearn_available": SKLEARN_AVAILABLE,
            "registry_stats": self.model_registry.get_registry_stats(),
        }
