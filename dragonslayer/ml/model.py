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
ML Model Management
===================

Unified model lifecycle management for VMDragonSlayer.

This module consolidates model management functionality including versioning,
persistence, and deployment status tracking.
"""

import hashlib
import json
import logging
import pickle
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.exceptions import MLError

logger = logging.getLogger(__name__)

# Handle optional dependencies
try:
    import torch
    import torch.nn as nn

    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    import joblib

    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False


class ModelType(Enum):
    """Types of ML models."""

    PYTORCH = "pytorch"
    SKLEARN = "sklearn"
    TENSORFLOW = "tensorflow"
    ONNX = "onnx"
    CUSTOM = "custom"


class ModelStatus(Enum):
    """Model deployment status."""

    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    ARCHIVED = "archived"
    DEPRECATED = "deprecated"


@dataclass
class ModelMetadata:
    """Metadata for ML models."""

    model_id: str
    name: str
    version: str
    model_type: ModelType
    status: ModelStatus
    description: str
    created_at: datetime
    updated_at: datetime
    file_path: str
    file_size: int
    checksum: str
    performance_metrics: Dict[str, float]
    training_config: Dict[str, Any]
    tags: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        data = asdict(self)
        data["model_type"] = self.model_type.value
        data["status"] = self.status.value
        data["created_at"] = self.created_at.isoformat()
        data["updated_at"] = self.updated_at.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ModelMetadata":
        """Create metadata from dictionary."""
        data["model_type"] = ModelType(data["model_type"])
        data["status"] = ModelStatus(data["status"])
        data["created_at"] = datetime.fromisoformat(data["created_at"])
        data["updated_at"] = datetime.fromisoformat(data["updated_at"])
        return cls(**data)


class MLModel:
    """
    Unified ML model wrapper with lifecycle management.

    This class provides a consistent interface for different types of ML models
    with built-in versioning, persistence, and metadata management.
    """

    def __init__(
        self,
        model: Any,
        name: str,
        version: str = "1.0.0",
        model_type: Optional[ModelType] = None,
        description: str = "",
        tags: Optional[List[str]] = None,
    ):
        """
        Initialize ML model wrapper.

        Args:
            model: The actual ML model object
            name: Human-readable model name
            version: Model version string
            model_type: Type of model (auto-detected if None)
            description: Model description
            tags: List of tags for organization
        """
        self.model = model
        self.model_id = str(uuid.uuid4())
        self.name = name
        self.version = version
        self.description = description
        self.tags = tags or []
        self.status = ModelStatus.DEVELOPMENT

        # Auto-detect model type if not provided
        if model_type is None:
            self.model_type = self._detect_model_type(model)
        else:
            self.model_type = model_type

        # Initialize metadata
        self.metadata = ModelMetadata(
            model_id=self.model_id,
            name=self.name,
            version=self.version,
            model_type=self.model_type,
            status=self.status,
            description=self.description,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            file_path="",
            file_size=0,
            checksum="",
            performance_metrics={},
            training_config={},
            tags=self.tags,
        )

        logger.info(
            f"Initialized MLModel: {self.name} v{self.version} ({self.model_type.value})"
        )

    def _detect_model_type(self, model: Any) -> ModelType:
        """Auto-detect model type based on model object."""
        if TORCH_AVAILABLE and isinstance(model, torch.nn.Module):
            return ModelType.PYTORCH
        elif hasattr(model, "fit") and hasattr(model, "predict"):
            # Likely sklearn-compatible model
            return ModelType.SKLEARN
        elif callable(model):
            # Custom callable model
            return ModelType.CUSTOM
        else:
            logger.warning(f"Could not detect model type for {type(model)}")
            return ModelType.CUSTOM

    def predict(self, X: Any) -> Any:
        """Make predictions with the model."""
        if self.model_type == ModelType.PYTORCH:
            return self._pytorch_predict(X)
        elif self.model_type == ModelType.SKLEARN:
            return self._sklearn_predict(X)
        else:
            # Try generic prediction
            if hasattr(self.model, "predict"):
                return self.model.predict(X)
            elif callable(self.model):
                return self.model(X)
            else:
                raise MLError(
                    f"Don't know how to predict with model type {self.model_type}"
                )

    def _pytorch_predict(self, X: Any) -> Any:
        """PyTorch-specific prediction."""
        if not TORCH_AVAILABLE:
            raise MLError("PyTorch not available for prediction")

        import torch

        self.model.eval()
        with torch.no_grad():
            if isinstance(X, torch.Tensor):
                return self.model(X)
            else:
                X_tensor = torch.FloatTensor(X)
                return self.model(X_tensor)

    def _sklearn_predict(self, X: Any) -> Any:
        """Scikit-learn prediction."""
        return self.model.predict(X)

    def evaluate(self, X: Any, y: Any) -> Dict[str, float]:
        """Evaluate model performance."""
        predictions = self.predict(X)

        # Basic accuracy calculation
        if hasattr(predictions, "numpy"):
            predictions = predictions.numpy()

        # For classification tasks
        if len(predictions.shape) > 1 and predictions.shape[1] > 1:
            # Multi-class predictions
            predictions = predictions.argmax(axis=1)

        accuracy = (predictions == y).mean()

        metrics = {"accuracy": float(accuracy)}

        # Update metadata
        self.metadata.performance_metrics.update(metrics)
        self.metadata.updated_at = datetime.now()

        return metrics

    def save(self, file_path: str, overwrite: bool = False) -> str:
        """
        Save model to file.

        Args:
            file_path: Path to save the model
            overwrite: Whether to overwrite existing file

        Returns:
            Path where model was saved
        """
        file_path = Path(file_path)

        if file_path.exists() and not overwrite:
            raise MLError(
                f"File {file_path} already exists. Use overwrite=True to replace."
            )

        # Create directory if needed
        file_path.parent.mkdir(parents=True, exist_ok=True)

        # Save based on model type
        if self.model_type == ModelType.PYTORCH:
            self._save_pytorch(file_path)
        elif self.model_type == ModelType.SKLEARN:
            self._save_sklearn(file_path)
        else:
            self._save_generic(file_path)

        # Update metadata
        self.metadata.file_path = str(file_path)
        self.metadata.file_size = file_path.stat().st_size
        self.metadata.checksum = self._calculate_checksum(file_path)
        self.metadata.updated_at = datetime.now()

        logger.info(f"Model saved to {file_path}")
        return str(file_path)

    def _save_pytorch(self, file_path: Path):
        """Save PyTorch model."""
        if not TORCH_AVAILABLE:
            raise MLError("PyTorch not available for saving")

        import torch

        # Save both model state and metadata
        save_data = {
            "model_state_dict": self.model.state_dict(),
            "model_class": type(self.model).__name__,
            "metadata": self.metadata.to_dict(),
        }

        torch.save(save_data, file_path)

    def _save_sklearn(self, file_path: Path):
        """Save scikit-learn model."""
        if not JOBLIB_AVAILABLE:
            # Fallback to pickle
            with open(file_path, "wb") as f:
                pickle.dump(
                    {"model": self.model, "metadata": self.metadata.to_dict()}, f
                )
        else:
            import joblib

            joblib.dump(
                {"model": self.model, "metadata": self.metadata.to_dict()}, file_path
            )

    def _save_generic(self, file_path: Path):
        """Save generic model using pickle."""
        with open(file_path, "wb") as f:
            pickle.dump({"model": self.model, "metadata": self.metadata.to_dict()}, f)

    @classmethod
    def load(cls, file_path: str) -> "MLModel":
        """
        Load model from file.

        Args:
            file_path: Path to model file

        Returns:
            Loaded MLModel instance
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise MLError(f"Model file {file_path} not found")

        # Try to determine format and load
        try:
            # Try PyTorch first
            if TORCH_AVAILABLE:
                import torch

                try:
                    data = torch.load(file_path, map_location="cpu")
                    if isinstance(data, dict) and "model_state_dict" in data:
                        return cls._load_pytorch(file_path, data)
                except Exception as e:
                    logger.debug(f"torch.load not a PyTorch state dict: {e}")

            # Try joblib
            if JOBLIB_AVAILABLE:
                import joblib

                try:
                    data = joblib.load(file_path)
                    if isinstance(data, dict) and "model" in data:
                        return cls._load_sklearn_joblib(file_path, data)
                except Exception as e:
                    logger.debug(f"joblib.load not a sklearn bundle: {e}")

            # SECURITY WARNING: Pickle deserialization can be dangerous
            # Only load pickle files from trusted sources
            # Consider using joblib or JSON for safer serialization
            try:
                # Verify file size is reasonable (< 100MB)
                if file_path.stat().st_size > 100 * 1024 * 1024:
                    raise MLError(f"Model file too large: {file_path}")
                
                with open(file_path, "rb") as f:
                    data = pickle.load(f)  # WARNING: Only use with trusted data
                    if isinstance(data, dict) and "model" in data:
                        return cls._load_pickle(file_path, data)
            except Exception as e:
                logger.warning(f"Pickle loading failed for {file_path}: {e}")
                raise MLError(f"Failed to load potentially unsafe pickle file: {file_path}")

            raise MLError(f"Could not determine format of model file {file_path}")

        except Exception as e:
            raise MLError(f"Failed to load model from {file_path}: {e}") from e

    @classmethod
    def _reconstruct_pytorch_model(cls, architecture: Dict) -> Any:
        """Reconstruct PyTorch model from architecture specification."""
        if not TORCH_AVAILABLE:
            raise MLError("PyTorch not available")
        
        model_type = architecture.get("type", "sequential")
        
        if model_type == "sequential":
            return cls._build_sequential_model(architecture)
        elif model_type == "custom":
            return cls._build_custom_model(architecture)
        elif model_type == "transformer":
            return cls._build_transformer_model(architecture)
        else:
            raise MLError(f"Unsupported PyTorch model type: {model_type}")
    
    @classmethod
    def _build_sequential_model(cls, architecture: Dict) -> Any:
        """Build sequential PyTorch model."""
        import torch.nn as nn
        
        layers = []
        layer_configs = architecture.get("layers", [])
        
        for layer_config in layer_configs:
            layer_type = layer_config.get("type")
            params = layer_config.get("params", {})
            
            if layer_type == "linear":
                layers.append(nn.Linear(**params))
            elif layer_type == "relu":
                layers.append(nn.ReLU())
            elif layer_type == "sigmoid":
                layers.append(nn.Sigmoid())
            elif layer_type == "tanh":
                layers.append(nn.Tanh())
            elif layer_type == "dropout":
                layers.append(nn.Dropout(**params))
            elif layer_type == "batch_norm":
                layers.append(nn.BatchNorm1d(**params))
            elif layer_type == "conv1d":
                layers.append(nn.Conv1d(**params))
            elif layer_type == "conv2d":
                layers.append(nn.Conv2d(**params))
            elif layer_type == "max_pool1d":
                layers.append(nn.MaxPool1d(**params))
            elif layer_type == "max_pool2d":
                layers.append(nn.MaxPool2d(**params))
            elif layer_type == "flatten":
                layers.append(nn.Flatten())
            else:
                logger.warning(f"Unknown layer type: {layer_type}, skipping")
        
        return nn.Sequential(*layers)
    
    @classmethod 
    def _build_custom_model(cls, architecture: Dict) -> Any:
        """Build custom PyTorch model from class specification."""
        import torch.nn as nn
        
        class CustomVMClassifier(nn.Module):
            def __init__(self, config):
                super().__init__()
                self.input_size = config.get("input_size", 1024)
                self.hidden_sizes = config.get("hidden_sizes", [512, 256, 128])
                self.num_classes = config.get("num_classes", 10)
                self.dropout_rate = config.get("dropout_rate", 0.5)
                
                # Build layers
                layers = []
                in_features = self.input_size
                
                for hidden_size in self.hidden_sizes:
                    layers.extend([
                        nn.Linear(in_features, hidden_size),
                        nn.ReLU(),
                        nn.BatchNorm1d(hidden_size),
                        nn.Dropout(self.dropout_rate)
                    ])
                    in_features = hidden_size
                
                layers.append(nn.Linear(in_features, self.num_classes))
                self.classifier = nn.Sequential(*layers)
            
            def forward(self, x):
                return self.classifier(x)
        
        config = architecture.get("config", {})
        return CustomVMClassifier(config)
    
    @classmethod
    def _build_transformer_model(cls, architecture: Dict) -> Any:
        """Build transformer-based PyTorch model."""
        import torch
        import torch.nn as nn
        
        class TransformerVMClassifier(nn.Module):
            def __init__(self, config):
                super().__init__()
                self.embed_dim = config.get("embed_dim", 512)
                self.num_heads = config.get("num_heads", 8)
                self.num_layers = config.get("num_layers", 6)
                self.num_classes = config.get("num_classes", 10)
                self.max_seq_len = config.get("max_seq_len", 1024)
                
                # Embedding layer
                self.embedding = nn.Linear(1, self.embed_dim)
                self.pos_encoding = nn.Parameter(torch.randn(self.max_seq_len, self.embed_dim))
                
                # Transformer layers
                encoder_layer = nn.TransformerEncoderLayer(
                    d_model=self.embed_dim,
                    nhead=self.num_heads,
                    dim_feedforward=self.embed_dim * 4,
                    dropout=0.1,
                    batch_first=True
                )
                self.transformer = nn.TransformerEncoder(
                    encoder_layer, 
                    num_layers=self.num_layers
                )
                
                # Classification head
                self.classifier = nn.Linear(self.embed_dim, self.num_classes)
                
            def forward(self, x):
                # x shape: (batch_size, seq_len)
                seq_len = x.size(1)
                
                # Embedding
                x = x.unsqueeze(-1)  # (batch_size, seq_len, 1)
                x = self.embedding(x)  # (batch_size, seq_len, embed_dim)
                
                # Add positional encoding
                x = x + self.pos_encoding[:seq_len, :]
                
                # Transformer encoding
                x = self.transformer(x)  # (batch_size, seq_len, embed_dim)
                
                # Global average pooling
                x = x.mean(dim=1)  # (batch_size, embed_dim)
                
                # Classification
                return self.classifier(x)
        
        config = architecture.get("config", {})
        return TransformerVMClassifier(config)

    @classmethod
    def _load_pytorch(cls, file_path: Path, data: Dict) -> "MLModel":
        """Load PyTorch model with architecture reconstruction."""
        if not TORCH_AVAILABLE:
            raise MLError("PyTorch not available for model loading")
            
        metadata = ModelMetadata.from_dict(data["metadata"])
        
        try:
            # Get model architecture info from metadata
            training_config = metadata.training_config
            architecture = training_config.get("architecture", {})
            
            if not architecture:
                raise MLError("Model architecture not found in metadata")
            
            # Reconstruct model architecture
            model = cls._reconstruct_pytorch_model(architecture)
            
            # Load state dict if available
            if "state_dict_path" in data:
                state_dict_path = file_path.parent / data["state_dict_path"]
                if state_dict_path.exists():
                    state_dict = torch.load(state_dict_path, map_location='cpu')
                    model.load_state_dict(state_dict)
                    logger.info(f"Loaded PyTorch model state from {state_dict_path}")
            elif "model_data" in data:
                # Direct state dict in data
                state_dict = data["model_data"]
                model.load_state_dict(state_dict)
                logger.info("Loaded PyTorch model state from metadata")
            else:
                logger.warning("No state dict found, using randomly initialized model")
            
            # Set model to evaluation mode
            model.eval()
            
            model_wrapper = cls.__new__(cls)
            model_wrapper.model = model
            model_wrapper.model_id = metadata.model_id
            model_wrapper.name = metadata.name
            model_wrapper.version = metadata.version
            model_wrapper.model_type = metadata.model_type
            model_wrapper.description = metadata.description
            model_wrapper.tags = metadata.tags
            model_wrapper.status = metadata.status
            model_wrapper.metadata = metadata
            
            logger.info(f"Successfully loaded PyTorch model: {metadata.name} v{metadata.version}")
            return model_wrapper
            
        except Exception as e:
            logger.error(f"Failed to load PyTorch model: {e}")
            raise MLError(f"PyTorch model loading failed: {e}") from e

    @classmethod
    def _load_sklearn_joblib(cls, file_path: Path, data: Dict) -> "MLModel":
        """Load scikit-learn model from joblib."""
        model = data["model"]
        metadata = ModelMetadata.from_dict(data["metadata"])

        model_wrapper = cls.__new__(cls)
        model_wrapper.model = model
        model_wrapper.model_id = metadata.model_id
        model_wrapper.name = metadata.name
        model_wrapper.version = metadata.version
        model_wrapper.model_type = metadata.model_type
        model_wrapper.description = metadata.description
        model_wrapper.tags = metadata.tags
        model_wrapper.status = metadata.status
        model_wrapper.metadata = metadata

        return model_wrapper

    @classmethod
    def _load_pickle(cls, file_path: Path, data: Dict) -> "MLModel":
        """Load model from pickle."""
        model = data["model"]
        metadata = ModelMetadata.from_dict(data["metadata"])

        model_wrapper = cls.__new__(cls)
        model_wrapper.model = model
        model_wrapper.model_id = metadata.model_id
        model_wrapper.name = metadata.name
        model_wrapper.version = metadata.version
        model_wrapper.model_type = metadata.model_type
        model_wrapper.description = metadata.description
        model_wrapper.tags = metadata.tags
        model_wrapper.status = metadata.status
        model_wrapper.metadata = metadata

        return model_wrapper

    def _calculate_checksum(self, file_path: Path) -> str:
        """Calculate SHA256 checksum of file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()

    def update_status(self, status: ModelStatus):
        """Update model deployment status."""
        self.status = status
        self.metadata.status = status
        self.metadata.updated_at = datetime.now()
        logger.info(f"Model {self.name} status updated to {status.value}")

    def add_tag(self, tag: str):
        """Add a tag to the model."""
        if tag not in self.tags:
            self.tags.append(tag)
            self.metadata.tags = self.tags
            self.metadata.updated_at = datetime.now()

    def remove_tag(self, tag: str):
        """Remove a tag from the model."""
        if tag in self.tags:
            self.tags.remove(tag)
            self.metadata.tags = self.tags
            self.metadata.updated_at = datetime.now()

    def get_info(self) -> Dict[str, Any]:
        """Get comprehensive model information."""
        return {
            "model_id": self.model_id,
            "name": self.name,
            "version": self.version,
            "model_type": self.model_type.value,
            "status": self.status.value,
            "description": self.description,
            "tags": self.tags,
            "created_at": self.metadata.created_at.isoformat(),
            "updated_at": self.metadata.updated_at.isoformat(),
            "file_info": {
                "path": self.metadata.file_path,
                "size": self.metadata.file_size,
                "checksum": self.metadata.checksum,
            },
            "performance_metrics": self.metadata.performance_metrics,
            "training_config": self.metadata.training_config,
        }


class ModelRegistry:
    """
    Registry for managing multiple ML models with versioning and lifecycle management.
    """

    def __init__(self, registry_path: str = "data/model_registry.db"):
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_database()

        logger.info(f"Initialized ModelRegistry at {registry_path}")

    def _init_database(self):
        """Initialize SQLite database for model registry."""
        with sqlite3.connect(self.registry_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS models (
                    model_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    version TEXT NOT NULL,
                    model_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    description TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    file_path TEXT,
                    file_size INTEGER,
                    checksum TEXT,
                    performance_metrics TEXT,
                    training_config TEXT,
                    tags TEXT
                )
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_name_version ON models (name, version)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_status ON models (status)
            """
            )

    def register_model(self, model: MLModel) -> str:
        """
        Register a model in the registry.

        Args:
            model: MLModel to register

        Returns:
            Model ID
        """
        with self._lock:
            with sqlite3.connect(self.registry_path) as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO models
                    (model_id, name, version, model_type, status, description,
                     created_at, updated_at, file_path, file_size, checksum,
                     performance_metrics, training_config, tags)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        model.model_id,
                        model.name,
                        model.version,
                        model.model_type.value,
                        model.status.value,
                        model.description,
                        model.metadata.created_at.isoformat(),
                        model.metadata.updated_at.isoformat(),
                        model.metadata.file_path,
                        model.metadata.file_size,
                        model.metadata.checksum,
                        json.dumps(model.metadata.performance_metrics),
                        json.dumps(model.metadata.training_config),
                        json.dumps(model.tags),
                    ),
                )

        logger.info(
            f"Registered model {model.name} v{model.version} with ID {model.model_id}"
        )
        return model.model_id

    def get_model(self, model_id: str) -> Optional[ModelMetadata]:
        """Get model metadata by ID."""
        with sqlite3.connect(self.registry_path) as conn:
            conn.row_factory = sqlite3.Row
            result = conn.execute(
                "SELECT * FROM models WHERE model_id = ?", (model_id,)
            ).fetchone()

        if result:
            return self._row_to_metadata(result)
        return None

    def find_models(
        self,
        name: Optional[str] = None,
        version: Optional[str] = None,
        status: Optional[ModelStatus] = None,
        model_type: Optional[ModelType] = None,
        tags: Optional[List[str]] = None,
    ) -> List[ModelMetadata]:
        """Find models matching criteria."""
        query = "SELECT * FROM models WHERE 1=1"
        params = []

        if name:
            query += " AND name = ?"
            params.append(name)

        if version:
            query += " AND version = ?"
            params.append(version)

        if status:
            query += " AND status = ?"
            params.append(status.value)

        if model_type:
            query += " AND model_type = ?"
            params.append(model_type.value)

        with sqlite3.connect(self.registry_path) as conn:
            conn.row_factory = sqlite3.Row
            results = conn.execute(query, params).fetchall()

        models = [self._row_to_metadata(row) for row in results]

        # Filter by tags if specified
        if tags:
            filtered_models = []
            for model in models:
                if any(tag in model.tags for tag in tags):
                    filtered_models.append(model)
            models = filtered_models

        return models

    def get_latest_version(
        self, name: str, status: Optional[ModelStatus] = None
    ) -> Optional[ModelMetadata]:
        """Get the latest version of a model by name."""
        query = "SELECT * FROM models WHERE name = ?"
        params = [name]

        if status:
            query += " AND status = ?"
            params.append(status.value)

        query += " ORDER BY created_at DESC LIMIT 1"

        with sqlite3.connect(self.registry_path) as conn:
            conn.row_factory = sqlite3.Row
            result = conn.execute(query, params).fetchone()

        if result:
            return self._row_to_metadata(result)
        return None

    def update_model_status(self, model_id: str, status: ModelStatus):
        """Update model status in registry."""
        with self._lock:
            with sqlite3.connect(self.registry_path) as conn:
                conn.execute(
                    "UPDATE models SET status = ?, updated_at = ? WHERE model_id = ?",
                    (status.value, datetime.now().isoformat(), model_id),
                )

        logger.info(f"Updated model {model_id} status to {status.value}")

    def delete_model(self, model_id: str):
        """Remove model from registry."""
        with self._lock:
            with sqlite3.connect(self.registry_path) as conn:
                conn.execute("DELETE FROM models WHERE model_id = ?", (model_id,))

        logger.info(f"Deleted model {model_id} from registry")

    def _row_to_metadata(self, row) -> ModelMetadata:
        """Convert database row to ModelMetadata."""
        return ModelMetadata(
            model_id=row["model_id"],
            name=row["name"],
            version=row["version"],
            model_type=ModelType(row["model_type"]),
            status=ModelStatus(row["status"]),
            description=row["description"] or "",
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            file_path=row["file_path"] or "",
            file_size=row["file_size"] or 0,
            checksum=row["checksum"] or "",
            performance_metrics=json.loads(row["performance_metrics"] or "{}"),
            training_config=json.loads(row["training_config"] or "{}"),
            tags=json.loads(row["tags"] or "[]"),
        )

    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        with sqlite3.connect(self.registry_path) as conn:
            total_models = conn.execute("SELECT COUNT(*) FROM models").fetchone()[0]

            status_counts = conn.execute(
                """
                SELECT status, COUNT(*) as count
                FROM models
                GROUP BY status
            """
            ).fetchall()

            type_counts = conn.execute(
                """
                SELECT model_type, COUNT(*) as count
                FROM models
                GROUP BY model_type
            """
            ).fetchall()

        return {
            "total_models": total_models,
            "status_distribution": {row[0]: row[1] for row in status_counts},
            "type_distribution": {row[0]: row[1] for row in type_counts},
        }
