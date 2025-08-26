#!/usr/bin/env python3
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
Automated Model Training Pipeline
===============================

Comprehensive pipeline for training VM detection models with automated
data loading, feature extraction, model training, and validation.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Any, Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, StratifiedKFold
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Add VMDragonSlayer to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from dragonslayer.core.exceptions import VMDragonSlayerError
    from dragonslayer.ml.features import FeatureExtractor
    from dragonslayer.ml.models import ModelFactory
    from dragonslayer.data.loaders import DatasetLoader
    from dragonslayer.utils.logging import setup_logging
    DRAGONSLAYER_AVAILABLE = True
except ImportError as e:
    print(f"Warning: VMDragonSlayer modules not available: {e}")
    DRAGONSLAYER_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('model_training.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class DataLoader:
    """Loads and prepares training data from various sources"""
    
    def __init__(self, data_config: Dict[str, Any]):
        self.config = data_config
        self.samples = []
        self.labels = []
        self.metadata = []
        
    def load_training_data(self) -> Tuple[List[str], List[str], List[Dict]]:
        """Load training data from configured sources"""
        logger.info("Loading training data...")
        
        data_sources = self.config.get('data_sources', [])
        
        for source in data_sources:
            source_type = source.get('type')
            source_path = source.get('path')
            
            if source_type == 'directory':
                self._load_from_directory(source_path, source)
            elif source_type == 'csv':
                self._load_from_csv(source_path, source)
            elif source_type == 'json':
                self._load_from_json(source_path, source)
            else:
                logger.warning(f"Unknown source type: {source_type}")
        
        logger.info(f"Loaded {len(self.samples)} samples with {len(set(self.labels))} unique labels")
        
        return self.samples, self.labels, self.metadata
    
    def _load_from_directory(self, directory_path: str, config: Dict):
        """Load samples from directory structure"""
        base_path = Path(directory_path)
        
        if not base_path.exists():
            logger.error(f"Directory not found: {directory_path}")
            return
        
        # Expected structure: base_path/label/sample_files
        for label_dir in base_path.iterdir():
            if not label_dir.is_dir():
                continue
                
            label = label_dir.name
            logger.info(f"Loading samples for label: {label}")
            
            sample_count = 0
            for sample_file in label_dir.rglob('*'):
                if sample_file.is_file() and self._is_valid_sample(sample_file):
                    self.samples.append(str(sample_file))
                    self.labels.append(label)
                    self.metadata.append({
                        'source': 'directory',
                        'label': label,
                        'file_size': sample_file.stat().st_size,
                        'file_path': str(sample_file)
                    })
                    sample_count += 1
            
            logger.info(f"  Loaded {sample_count} samples for {label}")
    
    def _load_from_csv(self, csv_path: str, config: Dict):
        """Load sample paths and labels from CSV file"""
        try:
            df = pd.read_csv(csv_path)
            
            path_column = config.get('path_column', 'path')
            label_column = config.get('label_column', 'label')
            
            for _, row in df.iterrows():
                sample_path = row[path_column]
                label = row[label_column]
                
                if Path(sample_path).exists():
                    self.samples.append(sample_path)
                    self.labels.append(label)
                    self.metadata.append({
                        'source': 'csv',
                        'label': label,
                        'csv_row': row.to_dict()
                    })
                else:
                    logger.warning(f"Sample not found: {sample_path}")
                    
        except Exception as e:
            logger.error(f"Failed to load CSV {csv_path}: {e}")
    
    def _load_from_json(self, json_path: str, config: Dict):
        """Load samples from JSON manifest"""
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
            
            samples_data = data.get('samples', [])
            
            for sample_info in samples_data:
                sample_path = sample_info.get('path')
                label = sample_info.get('label')
                
                if sample_path and label and Path(sample_path).exists():
                    self.samples.append(sample_path)
                    self.labels.append(label)
                    self.metadata.append({
                        'source': 'json',
                        'label': label,
                        **sample_info
                    })
                    
        except Exception as e:
            logger.error(f"Failed to load JSON {json_path}: {e}")
    
    def _is_valid_sample(self, file_path: Path) -> bool:
        """Check if file is a valid binary sample"""
        valid_extensions = ['.exe', '.dll', '.bin', '.so', '.dylib', '']
        
        # Check file extension
        if file_path.suffix.lower() not in valid_extensions:
            return False
            
        # Check file size (reasonable limits)
        file_size = file_path.stat().st_size
        if file_size < 1024 or file_size > 100 * 1024 * 1024:  # 1KB - 100MB
            return False
            
        return True


class FeatureExtractor:
    """Extracts features from binary samples for ML training"""
    
    def __init__(self, feature_config: Dict[str, Any]):
        self.config = feature_config
        self.feature_types = feature_config.get('feature_types', [])
        self.cache_features = feature_config.get('cache_features', True)
        self.cache_dir = Path(feature_config.get('cache_dir', 'feature_cache'))
        
        if self.cache_features:
            self.cache_dir.mkdir(exist_ok=True)
    
    def extract_features_batch(self, sample_paths: List[str], 
                             labels: List[str]) -> Tuple[np.ndarray, np.ndarray]:
        """Extract features from batch of samples"""
        logger.info(f"Extracting features from {len(sample_paths)} samples...")
        
        features = []
        valid_labels = []
        
        for i, (sample_path, label) in enumerate(zip(sample_paths, labels)):
            try:
                # Check cache first
                if self.cache_features:
                    cached_features = self._load_cached_features(sample_path)
                    if cached_features is not None:
                        features.append(cached_features)
                        valid_labels.append(label)
                        continue
                
                # Extract features
                sample_features = self._extract_sample_features(sample_path)
                
                if sample_features is not None:
                    features.append(sample_features)
                    valid_labels.append(label)
                    
                    # Cache features
                    if self.cache_features:
                        self._cache_features(sample_path, sample_features)
                else:
                    logger.warning(f"Failed to extract features from {sample_path}")
                
                # Progress update
                if (i + 1) % 100 == 0:
                    logger.info(f"Processed {i + 1}/{len(sample_paths)} samples")
                    
            except Exception as e:
                logger.error(f"Error processing {sample_path}: {e}")
                continue
        
        if not features:
            raise VMDragonSlayerError("No valid features extracted")
        
        features_array = np.array(features)
        logger.info(f"Extracted feature matrix: {features_array.shape}")
        
        return features_array, np.array(valid_labels)
    
    def _extract_sample_features(self, sample_path: str) -> Optional[np.ndarray]:
        """Extract features from a single sample"""
        try:
            with open(sample_path, 'rb') as f:
                binary_data = f.read()
            
            feature_vector = []
            
            # Basic file statistics
            if 'file_stats' in self.feature_types:
                stats_features = self._extract_file_stats(binary_data)
                feature_vector.extend(stats_features)
            
            # Entropy analysis
            if 'entropy' in self.feature_types:
                entropy_features = self._extract_entropy_features(binary_data)
                feature_vector.extend(entropy_features)
            
            # Byte distribution
            if 'byte_distribution' in self.feature_types:
                byte_features = self._extract_byte_distribution(binary_data)
                feature_vector.extend(byte_features)
            
            # N-gram analysis
            if 'ngrams' in self.feature_types:
                ngram_features = self._extract_ngram_features(binary_data)
                feature_vector.extend(ngram_features)
            
            # Opcode patterns (if available)
            if 'opcodes' in self.feature_types and DRAGONSLAYER_AVAILABLE:
                opcode_features = self._extract_opcode_features(binary_data)
                feature_vector.extend(opcode_features)
            
            return np.array(feature_vector, dtype=np.float32)
            
        except Exception as e:
            logger.error(f"Feature extraction failed for {sample_path}: {e}")
            return None
    
    def _extract_file_stats(self, binary_data: bytes) -> List[float]:
        """Extract basic file statistics"""
        return [
            len(binary_data),  # File size
            len(binary_data) / 1024.0,  # Size in KB
            binary_data.count(b'\x00') / len(binary_data),  # Null byte ratio
            binary_data.count(b'\xff') / len(binary_data),  # 0xFF byte ratio
        ]
    
    def _extract_entropy_features(self, binary_data: bytes) -> List[float]:
        """Extract entropy-based features"""
        from collections import Counter
        import math
        
        # Overall entropy
        byte_counts = Counter(binary_data)
        total_bytes = len(binary_data)
        
        entropy = 0.0
        for count in byte_counts.values():
            p = count / total_bytes
            if p > 0:
                entropy -= p * math.log2(p)
        
        # Chunk-based entropy analysis
        chunk_size = min(1024, len(binary_data) // 10)
        chunk_entropies = []
        
        for i in range(0, len(binary_data), chunk_size):
            chunk = binary_data[i:i + chunk_size]
            if len(chunk) > 0:
                chunk_counter = Counter(chunk)
                chunk_entropy = 0.0
                for count in chunk_counter.values():
                    p = count / len(chunk)
                    if p > 0:
                        chunk_entropy -= p * math.log2(p)
                chunk_entropies.append(chunk_entropy)
        
        return [
            entropy,  # Overall entropy
            np.mean(chunk_entropies) if chunk_entropies else 0.0,  # Mean chunk entropy
            np.std(chunk_entropies) if chunk_entropies else 0.0,   # Std chunk entropy
            max(chunk_entropies) if chunk_entropies else 0.0,      # Max chunk entropy
            min(chunk_entropies) if chunk_entropies else 0.0       # Min chunk entropy
        ]
    
    def _extract_byte_distribution(self, binary_data: bytes) -> List[float]:
        """Extract byte frequency distribution features"""
        byte_counts = [0] * 256
        
        for byte in binary_data:
            byte_counts[byte] += 1
        
        # Normalize by file size
        total = len(binary_data)
        if total > 0:
            byte_frequencies = [count / total for count in byte_counts]
        else:
            byte_frequencies = [0.0] * 256
        
        return byte_frequencies
    
    def _extract_ngram_features(self, binary_data: bytes) -> List[float]:
        """Extract n-gram frequency features"""
        # 2-gram and 3-gram analysis
        ngram_features = []
        
        # 2-grams (most common)
        bigram_counts = {}
        for i in range(len(binary_data) - 1):
            bigram = binary_data[i:i+2]
            bigram_counts[bigram] = bigram_counts.get(bigram, 0) + 1
        
        # Top 50 most common 2-grams
        top_bigrams = sorted(bigram_counts.items(), key=lambda x: x[1], reverse=True)[:50]
        bigram_features = [count / len(binary_data) for _, count in top_bigrams]
        
        # Pad to exactly 50 features
        while len(bigram_features) < 50:
            bigram_features.append(0.0)
        
        ngram_features.extend(bigram_features)
        
        return ngram_features
    
    def _extract_opcode_features(self, binary_data: bytes) -> List[float]:
        """Extract opcode-based features (simplified)"""
        # Simplified opcode pattern detection
        # In a full implementation, this would use disassembly
        
        opcode_patterns = [
            b'\x90',        # NOP
            b'\xCC',        # INT3
            b'\xE8',        # CALL
            b'\xE9',        # JMP
            b'\xEB',        # JMP short
            b'\x74',        # JZ
            b'\x75',        # JNZ
            b'\x8B',        # MOV
            b'\x89',        # MOV
            b'\x48',        # REX prefix (x64)
        ]
        
        pattern_counts = []
        for pattern in opcode_patterns:
            count = binary_data.count(pattern)
            pattern_counts.append(count / len(binary_data) if len(binary_data) > 0 else 0.0)
        
        return pattern_counts
    
    def _load_cached_features(self, sample_path: str) -> Optional[np.ndarray]:
        """Load cached features for a sample"""
        if not self.cache_features:
            return None
            
        cache_key = self._get_cache_key(sample_path)
        cache_file = self.cache_dir / f"{cache_key}.npy"
        
        if cache_file.exists():
            try:
                return np.load(cache_file)
            except Exception:
                # Remove corrupted cache file
                cache_file.unlink(missing_ok=True)
        
        return None
    
    def _cache_features(self, sample_path: str, features: np.ndarray):
        """Cache extracted features"""
        if not self.cache_features:
            return
            
        cache_key = self._get_cache_key(sample_path)
        cache_file = self.cache_dir / f"{cache_key}.npy"
        
        try:
            np.save(cache_file, features)
        except Exception as e:
            logger.warning(f"Failed to cache features for {sample_path}: {e}")
    
    def _get_cache_key(self, sample_path: str) -> str:
        """Generate cache key for sample"""
        import hashlib
        
        # Use file path and modification time for cache key
        sample_stat = Path(sample_path).stat()
        cache_input = f"{sample_path}_{sample_stat.st_size}_{sample_stat.st_mtime}"
        
        return hashlib.md5(cache_input.encode()).hexdigest()


class ModelTrainer:
    """Trains ML models for VM detection"""
    
    def __init__(self, training_config: Dict[str, Any]):
        self.config = training_config
        self.models = {}
        self.scalers = {}
        self.label_encoders = {}
        
    def train_models(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """Train multiple models and return results"""
        logger.info(f"Training models on dataset: {X.shape}")
        
        # Encode labels
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
        self.label_encoders['main'] = label_encoder
        
        # Split data
        test_size = self.config.get('test_size', 0.2)
        random_state = self.config.get('random_state', 42)
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_encoded, test_size=test_size, random_state=random_state, stratify=y_encoded
        )
        
        # Feature scaling
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        self.scalers['main'] = scaler
        
        logger.info(f"Training set: {X_train_scaled.shape}, Test set: {X_test_scaled.shape}")
        
        # Train configured models
        model_configs = self.config.get('models', {})
        results = {}
        
        for model_name, model_config in model_configs.items():
            logger.info(f"Training {model_name}...")
            
            try:
                # Create and train model
                model = self._create_model(model_name, model_config)
                
                train_start = time.time()
                model.fit(X_train_scaled, y_train)
                train_time = time.time() - train_start
                
                self.models[model_name] = model
                
                # Evaluate model
                model_results = self._evaluate_model(
                    model, X_train_scaled, y_train, X_test_scaled, y_test,
                    label_encoder, train_time
                )
                
                results[model_name] = model_results
                
                logger.info(f"  {model_name} - Accuracy: {model_results['test_accuracy']:.4f}")
                
            except Exception as e:
                logger.error(f"Failed to train {model_name}: {e}")
                results[model_name] = {'error': str(e)}
        
        return results
    
    def _create_model(self, model_name: str, model_config: Dict[str, Any]):
        """Create model instance based on configuration"""
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.svm import SVC
        from sklearn.linear_model import LogisticRegression
        from sklearn.neural_network import MLPClassifier
        
        model_type = model_config.get('type', model_name.lower())
        params = model_config.get('parameters', {})
        
        if model_type in ['random_forest', 'rf']:
            return RandomForestClassifier(**params)
        elif model_type in ['gradient_boosting', 'gb']:
            return GradientBoostingClassifier(**params)
        elif model_type in ['svm', 'svc']:
            return SVC(**params)
        elif model_type in ['logistic_regression', 'lr']:
            return LogisticRegression(**params)
        elif model_type in ['neural_network', 'mlp']:
            return MLPClassifier(**params)
        else:
            raise ValueError(f"Unknown model type: {model_type}")
    
    def _evaluate_model(self, model, X_train, y_train, X_test, y_test, 
                       label_encoder, train_time: float) -> Dict[str, Any]:
        """Evaluate trained model"""
        # Predictions
        y_train_pred = model.predict(X_train)
        y_test_pred = model.predict(X_test)
        
        # Probabilities (if available)
        train_proba = None
        test_proba = None
        if hasattr(model, 'predict_proba'):
            train_proba = model.predict_proba(X_train)
            test_proba = model.predict_proba(X_test)
        
        # Metrics
        from sklearn.metrics import accuracy_score, precision_recall_fscore_support
        
        train_accuracy = accuracy_score(y_train, y_train_pred)
        test_accuracy = accuracy_score(y_test, y_test_pred)
        
        # Per-class metrics
        precision, recall, f1, support = precision_recall_fscore_support(
            y_test, y_test_pred, average='weighted'
        )
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_test_pred)
        
        # Classification report
        class_names = label_encoder.classes_
        report = classification_report(
            y_test, y_test_pred, 
            target_names=class_names,
            output_dict=True
        )
        
        return {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm.tolist(),
            'classification_report': report,
            'class_names': class_names.tolist(),
            'train_time': train_time,
            'model_type': type(model).__name__
        }
    
    def save_models(self, output_dir: str, results: Dict[str, Any]):
        """Save trained models and metadata"""
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Save models
        import joblib
        
        for model_name, model in self.models.items():
            model_file = output_path / f"{model_name}_model.joblib"
            joblib.dump(model, model_file)
            logger.info(f"Saved model: {model_file}")
        
        # Save scalers
        for scaler_name, scaler in self.scalers.items():
            scaler_file = output_path / f"{scaler_name}_scaler.joblib"
            joblib.dump(scaler, scaler_file)
        
        # Save label encoders
        for encoder_name, encoder in self.label_encoders.items():
            encoder_file = output_path / f"{encoder_name}_label_encoder.joblib"
            joblib.dump(encoder, encoder_file)
        
        # Save results
        results_file = output_path / "training_results.json"
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        
        logger.info(f"Saved training results: {results_file}")


class ValidationPipeline:
    """Comprehensive model validation using cross-validation"""
    
    def __init__(self, validation_config: Dict[str, Any]):
        self.config = validation_config
        
    def cross_validate_models(self, X: np.ndarray, y: np.ndarray, 
                            models_config: Dict[str, Any]) -> Dict[str, Any]:
        """Perform k-fold cross-validation on models"""
        
        n_folds = self.config.get('n_folds', 5)
        random_state = self.config.get('random_state', 42)
        
        logger.info(f"Starting {n_folds}-fold cross-validation...")
        
        # Prepare data
        label_encoder = LabelEncoder()
        y_encoded = label_encoder.fit_transform(y)
        
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Cross-validation setup
        kfold = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=random_state)
        
        cv_results = {}
        
        for model_name, model_config in models_config.items():
            logger.info(f"Cross-validating {model_name}...")
            
            fold_results = []
            
            for fold, (train_idx, val_idx) in enumerate(kfold.split(X_scaled, y_encoded)):
                logger.info(f"  Fold {fold + 1}/{n_folds}")
                
                # Split data
                X_train_fold = X_scaled[train_idx]
                y_train_fold = y_encoded[train_idx]
                X_val_fold = X_scaled[val_idx]
                y_val_fold = y_encoded[val_idx]
                
                try:
                    # Create and train model
                    trainer = ModelTrainer({'models': {model_name: model_config}})
                    model = trainer._create_model(model_name, model_config)
                    
                    # Train
                    model.fit(X_train_fold, y_train_fold)
                    
                    # Evaluate
                    y_pred = model.predict(X_val_fold)
                    accuracy = accuracy_score(y_val_fold, y_pred)
                    
                    fold_results.append({
                        'fold': fold,
                        'accuracy': accuracy,
                        'train_size': len(X_train_fold),
                        'val_size': len(X_val_fold)
                    })
                    
                except Exception as e:
                    logger.error(f"  Fold {fold + 1} failed: {e}")
                    fold_results.append({
                        'fold': fold,
                        'error': str(e)
                    })
            
            # Aggregate results
            valid_results = [r for r in fold_results if 'error' not in r]
            
            if valid_results:
                accuracies = [r['accuracy'] for r in valid_results]
                cv_results[model_name] = {
                    'mean_accuracy': np.mean(accuracies),
                    'std_accuracy': np.std(accuracies),
                    'fold_results': fold_results,
                    'n_successful_folds': len(valid_results)
                }
                
                logger.info(f"  {model_name} CV: {np.mean(accuracies):.4f} ± {np.std(accuracies):.4f}")
            else:
                cv_results[model_name] = {
                    'error': 'All folds failed',
                    'fold_results': fold_results
                }
        
        return cv_results


def load_config(config_path: str) -> Dict[str, Any]:
    """Load configuration from JSON file"""
    with open(config_path, 'r') as f:
        return json.load(f)


def main():
    """Main training pipeline execution"""
    parser = argparse.ArgumentParser(description="Train VM detection models")
    parser.add_argument('--config', '-c', required=True,
                       help='Path to training configuration file')
    parser.add_argument('--output', '-o', default='models',
                       help='Output directory for trained models')
    parser.add_argument('--cross-validate', action='store_true',
                       help='Perform cross-validation')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Load configuration
        logger.info(f"Loading configuration from: {args.config}")
        config = load_config(args.config)
        
        # Initialize components
        data_loader = DataLoader(config.get('data', {}))
        feature_extractor = FeatureExtractor(config.get('features', {}))
        model_trainer = ModelTrainer(config.get('training', {}))
        
        # Load data
        sample_paths, labels, metadata = data_loader.load_training_data()
        
        if not sample_paths:
            raise VMDragonSlayerError("No training samples loaded")
        
        # Extract features
        X, y = feature_extractor.extract_features_batch(sample_paths, labels)
        
        logger.info(f"Dataset prepared: {X.shape} features, {len(set(y))} classes")
        
        # Cross-validation (if requested)
        if args.cross_validate:
            validator = ValidationPipeline(config.get('validation', {}))
            cv_results = validator.cross_validate_models(X, y, config['training']['models'])
            
            # Save CV results
            cv_output_file = Path(args.output) / "cross_validation_results.json"
            cv_output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(cv_output_file, 'w') as f:
                json.dump(cv_results, f, indent=2, default=str)
            
            logger.info(f"Cross-validation results saved: {cv_output_file}")
        
        # Train final models
        logger.info("Training final models...")
        training_results = model_trainer.train_models(X, y)
        
        # Save models and results
        model_trainer.save_models(args.output, training_results)
        
        # Print summary
        logger.info("Training completed successfully!")
        logger.info("Model performance summary:")
        
        for model_name, results in training_results.items():
            if 'error' not in results:
                logger.info(f"  {model_name}: {results['test_accuracy']:.4f} accuracy")
            else:
                logger.error(f"  {model_name}: {results['error']}")
        
    except Exception as e:
        logger.error(f"Training pipeline failed: {e}")
        raise


if __name__ == "__main__":
    main()
