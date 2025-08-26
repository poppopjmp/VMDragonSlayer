# Model Training Guide
# VMDragonSlayer Custom VM Detection Models

This comprehensive guide will walk you through the process of creating, training, and integrating custom virtual machine (VM) detection models with VMDragonSlayer.

## Table of Contents

1. [Overview](#overview)
2. [Data Collection and Preparation](#data-collection-and-preparation)
3. [Feature Engineering for VM Patterns](#feature-engineering-for-vm-patterns)
4. [Training Pipeline Configuration](#training-pipeline-configuration)
5. [Model Validation and Testing](#model-validation-and-testing)
6. [Integration with Pattern Database](#integration-with-pattern-database)
7. [Advanced Topics](#advanced-topics)
8. [Troubleshooting](#troubleshooting)

## Overview

VMDragonSlayer supports custom machine learning models for detecting various types of virtual machine obfuscation and packing techniques. This guide covers the complete workflow from data collection to production deployment.

### Supported Model Types

- **Binary Classification Models**: Detect VM presence (VM vs. non-VM)
- **Multi-class Classification**: Identify specific VM types (VMProtect, Themida, custom VMs)
- **Sequence Models**: Analyze instruction sequences for VM patterns
- **Graph Neural Networks**: Model control flow and data flow relationships

### Prerequisites

Before starting, ensure you have:
- Python 3.8+ with VMDragonSlayer installed
- Sufficient training data (minimum 1000 samples per class)
- Computational resources (GPU recommended for large datasets)
- Domain expertise in reverse engineering and VM obfuscation

## Data Collection and Preparation

### 1. Sample Collection

#### Binary Sample Requirements

```python
# Example directory structure for training data
training_data/
├── vm_samples/
│   ├── vmprotect/
│   │   ├── sample001.exe
│   │   ├── sample002.exe
│   │   └── ...
│   ├── themida/
│   │   ├── sample001.exe
│   │   └── ...
│   └── custom_vm/
│       ├── sample001.exe
│       └── ...
├── clean_samples/
│   ├── native001.exe
│   ├── native002.exe
│   └── ...
└── metadata.json
```

#### Sample Quality Guidelines

1. **Diversity**: Include samples from different compilers, architectures, and time periods
2. **Balance**: Maintain roughly equal samples per class to avoid bias
3. **Verification**: Manually verify sample labels to ensure accuracy
4. **Size**: Aim for at least 1000 samples per VM type

#### Automated Sample Collection

```python
from dragonslayer.data.collectors import BinarySampleCollector
from dragonslayer.data.validators import SampleValidator

# Initialize sample collector
collector = BinarySampleCollector(
    output_dir="training_data",
    min_size=1024,  # Minimum file size in bytes
    max_size=50 * 1024 * 1024,  # Maximum 50MB
    architectures=["x86", "x64"],
    file_types=[".exe", ".dll"]
)

# Collect samples with automatic labeling
vm_samples = collector.collect_from_malware_datasets([
    "malware_dataset_1",
    "custom_vm_samples"
])

# Validate sample quality
validator = SampleValidator()
valid_samples = validator.validate_samples(vm_samples)
```

### 2. Data Preprocessing

#### Binary Feature Extraction

```python
from dragonslayer.ml.extractors import BinaryFeatureExtractor

# Initialize feature extractor
extractor = BinaryFeatureExtractor(
    features=[
        "opcode_frequencies",
        "control_flow_graph", 
        "data_flow_patterns",
        "entropy_analysis",
        "section_characteristics",
        "import_api_patterns"
    ]
)

# Process samples
processed_samples = []
for sample_path in sample_paths:
    features = extractor.extract_features(sample_path)
    processed_samples.append(features)
```

#### Feature Vector Generation

```python
from dragonslayer.ml.features import VMPatternFeatures

# Generate comprehensive feature vectors
feature_generator = VMPatternFeatures()

training_vectors = []
labels = []

for sample in processed_samples:
    # Extract VM-specific patterns
    vm_features = feature_generator.extract_vm_patterns(sample)
    
    # Create feature vector
    feature_vector = vm_features.to_vector()
    training_vectors.append(feature_vector)
    labels.append(sample.label)
```

## Feature Engineering for VM Patterns

### 1. Static Analysis Features

#### Opcode Pattern Features

```python
from dragonslayer.analysis.static import OpcodePatternAnalyzer

class VMOpcodeFeatures:
    def __init__(self):
        self.analyzer = OpcodePatternAnalyzer()
        
    def extract_features(self, binary_data):
        """Extract VM-specific opcode patterns"""
        features = {}
        
        # Instruction frequency analysis
        opcodes = self.analyzer.get_opcode_frequencies(binary_data)
        features.update(self._normalize_opcodes(opcodes))
        
        # VM dispatch patterns
        dispatch_patterns = self.analyzer.find_dispatch_patterns(binary_data)
        features['dispatch_complexity'] = len(dispatch_patterns)
        features['dispatch_entropy'] = self._calculate_entropy(dispatch_patterns)
        
        # Handler pattern recognition
        handler_patterns = self.analyzer.find_handler_patterns(binary_data)
        features['handler_count'] = len(handler_patterns)
        features['avg_handler_size'] = self._avg_handler_size(handler_patterns)
        
        return features
    
    def _normalize_opcodes(self, opcodes):
        """Normalize opcode frequencies"""
        total = sum(opcodes.values())
        return {f"opcode_{k}": v/total for k, v in opcodes.items()}
```

#### Control Flow Graph Features

```python
from dragonslayer.analysis.cfg import ControlFlowAnalyzer

class VMControlFlowFeatures:
    def __init__(self):
        self.cfg_analyzer = ControlFlowAnalyzer()
        
    def extract_features(self, binary_data):
        """Extract control flow features indicative of VM presence"""
        cfg = self.cfg_analyzer.build_cfg(binary_data)
        
        features = {
            # Graph topology metrics
            'cfg_nodes': len(cfg.nodes),
            'cfg_edges': len(cfg.edges), 
            'cfg_density': len(cfg.edges) / (len(cfg.nodes) * (len(cfg.nodes) - 1)),
            'cyclomatic_complexity': self._cyclomatic_complexity(cfg),
            
            # VM-specific patterns
            'indirect_jumps': self._count_indirect_jumps(cfg),
            'computed_jumps': self._count_computed_jumps(cfg),
            'dispatcher_candidates': self._find_dispatcher_nodes(cfg),
            
            # Structural anomalies
            'unreachable_code': self._count_unreachable_code(cfg),
            'obfuscated_branches': self._detect_obfuscated_branches(cfg)
        }
        
        return features
```

### 2. Dynamic Analysis Features

#### Runtime Behavior Patterns

```python
from dragonslayer.analysis.dynamic import RuntimeTracer

class VMRuntimeFeatures:
    def __init__(self):
        self.tracer = RuntimeTracer()
        
    def extract_features(self, binary_path, timeout=60):
        """Extract runtime behavior features"""
        trace = self.tracer.trace_execution(binary_path, timeout=timeout)
        
        features = {
            # Execution patterns
            'instruction_count': len(trace.instructions),
            'unique_addresses': len(set(trace.addresses)),
            'address_entropy': self._calculate_address_entropy(trace.addresses),
            
            # VM interpreter patterns
            'interpretation_loops': self._detect_interpretation_loops(trace),
            'vm_register_usage': self._analyze_vm_registers(trace),
            'context_switches': self._count_context_switches(trace),
            
            # Performance indicators
            'avg_instructions_per_second': trace.instruction_count / trace.duration,
            'memory_access_patterns': self._analyze_memory_access(trace)
        }
        
        return features
```

### 3. Hybrid Feature Combination

```python
class HybridVMFeatures:
    def __init__(self):
        self.static_extractor = VMOpcodeFeatures()
        self.cfg_extractor = VMControlFlowFeatures()
        self.runtime_extractor = VMRuntimeFeatures()
        
    def extract_comprehensive_features(self, binary_path):
        """Combine static and dynamic features"""
        # Static analysis
        with open(binary_path, 'rb') as f:
            binary_data = f.read()
            
        static_features = self.static_extractor.extract_features(binary_data)
        cfg_features = self.cfg_extractor.extract_features(binary_data)
        
        # Dynamic analysis (optional, time-consuming)
        runtime_features = self.runtime_extractor.extract_features(binary_path)
        
        # Combine all features
        combined_features = {
            **static_features,
            **cfg_features, 
            **runtime_features
        }
        
        return combined_features
```

## Training Pipeline Configuration

### 1. Model Architecture Selection

#### Traditional ML Models

```python
from dragonslayer.ml.models import VMClassifier
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.svm import SVC

# Configure different model architectures
model_configs = {
    'random_forest': {
        'model': RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            random_state=42
        ),
        'hyperparams': {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 20, 30],
            'min_samples_split': [2, 5, 10]
        }
    },
    
    'gradient_boosting': {
        'model': GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=10,
            random_state=42
        ),
        'hyperparams': {
            'n_estimators': [50, 100, 200],
            'learning_rate': [0.01, 0.1, 0.2],
            'max_depth': [5, 10, 15]
        }
    },
    
    'svm': {
        'model': SVC(
            kernel='rbf',
            C=1.0,
            gamma='scale',
            probability=True
        ),
        'hyperparams': {
            'C': [0.1, 1.0, 10.0],
            'gamma': ['scale', 'auto', 0.001, 0.01]
        }
    }
}
```

#### Deep Learning Models

```python
import torch
import torch.nn as nn
from dragonslayer.ml.neural import VMDetectionNet

class VMTransformerModel(nn.Module):
    def __init__(self, input_dim, hidden_dim=256, num_heads=8, num_layers=6):
        super().__init__()
        self.embedding = nn.Linear(input_dim, hidden_dim)
        
        # Transformer encoder for sequence modeling
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=hidden_dim,
            nhead=num_heads,
            dim_feedforward=hidden_dim*4,
            dropout=0.1
        )
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers)
        
        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(hidden_dim, hidden_dim//2),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_dim//2, num_classes)
        )
        
    def forward(self, x):
        x = self.embedding(x)
        x = self.transformer(x)
        x = x.mean(dim=1)  # Global average pooling
        return self.classifier(x)

# Model configuration
model_config = {
    'architecture': 'transformer',
    'input_dim': 1024,  # Feature vector size
    'hidden_dim': 256,
    'num_heads': 8,
    'num_layers': 6,
    'num_classes': 4,  # clean, vmprotect, themida, custom
    'learning_rate': 0.001,
    'batch_size': 32,
    'epochs': 100
}
```

### 2. Training Pipeline Implementation

```python
from dragonslayer.ml.training import VMModelTrainer
from dragonslayer.ml.validation import CrossValidator
import wandb  # For experiment tracking

class VMTrainingPipeline:
    def __init__(self, config):
        self.config = config
        self.trainer = VMModelTrainer(config)
        self.validator = CrossValidator(k_folds=5)
        
        # Initialize experiment tracking
        wandb.init(project="vmdragonslayer-models", config=config)
        
    def run_training(self, X_train, y_train, X_val, y_val):
        """Execute complete training pipeline"""
        
        # 1. Data preprocessing
        X_train_processed = self.trainer.preprocess_features(X_train)
        X_val_processed = self.trainer.preprocess_features(X_val)
        
        # 2. Model initialization
        model = self.trainer.initialize_model(self.config['architecture'])
        
        # 3. Training loop with early stopping
        best_model = None
        best_score = 0
        patience_counter = 0
        
        for epoch in range(self.config['epochs']):
            # Training step
            train_loss, train_acc = self.trainer.train_epoch(
                model, X_train_processed, y_train
            )
            
            # Validation step  
            val_loss, val_acc = self.trainer.validate_epoch(
                model, X_val_processed, y_val
            )
            
            # Log metrics
            wandb.log({
                'epoch': epoch,
                'train_loss': train_loss,
                'train_acc': train_acc,
                'val_loss': val_loss,
                'val_acc': val_acc
            })
            
            # Early stopping
            if val_acc > best_score:
                best_score = val_acc
                best_model = model.state_dict().copy()
                patience_counter = 0
            else:
                patience_counter += 1
                
            if patience_counter >= self.config['patience']:
                print(f"Early stopping at epoch {epoch}")
                break
        
        # Load best model
        model.load_state_dict(best_model)
        
        return model, best_score
```

### 3. Hyperparameter Optimization

```python
from optuna import create_study, Trial
from dragonslayer.ml.optimization import VMHyperparameterOptimizer

class VMHyperparameterOptimizer:
    def __init__(self, X_train, y_train, X_val, y_val):
        self.X_train = X_train
        self.y_train = y_train
        self.X_val = X_val
        self.y_val = y_val
        
    def objective(self, trial: Trial) -> float:
        """Optuna objective function for hyperparameter optimization"""
        
        # Sample hyperparameters
        params = {
            'learning_rate': trial.suggest_float('learning_rate', 1e-5, 1e-1, log=True),
            'hidden_dim': trial.suggest_categorical('hidden_dim', [128, 256, 512]),
            'num_layers': trial.suggest_int('num_layers', 2, 8),
            'dropout': trial.suggest_float('dropout', 0.1, 0.5),
            'batch_size': trial.suggest_categorical('batch_size', [16, 32, 64])
        }
        
        # Create and train model
        trainer = VMModelTrainer(params)
        model = trainer.initialize_model('transformer')
        
        # Training with early stopping
        best_val_acc = 0
        for epoch in range(50):  # Reduced epochs for optimization
            trainer.train_epoch(model, self.X_train, self.y_train)
            _, val_acc = trainer.validate_epoch(model, self.X_val, self.y_val)
            
            if val_acc > best_val_acc:
                best_val_acc = val_acc
                
        return best_val_acc
    
    def optimize(self, n_trials=100):
        """Run hyperparameter optimization"""
        study = create_study(direction='maximize')
        study.optimize(self.objective, n_trials=n_trials)
        
        return study.best_params, study.best_value

# Usage example
optimizer = VMHyperparameterOptimizer(X_train, y_train, X_val, y_val)
best_params, best_score = optimizer.optimize(n_trials=50)
print(f"Best parameters: {best_params}")
print(f"Best validation accuracy: {best_score}")
```

## Model Validation and Testing

### 1. Cross-Validation Strategy

```python
from sklearn.model_selection import StratifiedKFold
from dragonslayer.ml.metrics import VMDetectionMetrics

class VMModelValidator:
    def __init__(self, n_folds=5):
        self.n_folds = n_folds
        self.kfold = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=42)
        self.metrics = VMDetectionMetrics()
        
    def cross_validate(self, X, y, model_class, model_params):
        """Perform k-fold cross-validation"""
        fold_scores = []
        fold_reports = []
        
        for fold, (train_idx, val_idx) in enumerate(self.kfold.split(X, y)):
            print(f"Training fold {fold + 1}/{self.n_folds}")
            
            # Split data
            X_train_fold = X[train_idx]
            y_train_fold = y[train_idx]
            X_val_fold = X[val_idx]
            y_val_fold = y[val_idx]
            
            # Train model
            model = model_class(**model_params)
            model.fit(X_train_fold, y_train_fold)
            
            # Evaluate
            y_pred = model.predict(X_val_fold)
            y_proba = model.predict_proba(X_val_fold) if hasattr(model, 'predict_proba') else None
            
            # Calculate metrics
            fold_score = self.metrics.accuracy_score(y_val_fold, y_pred)
            fold_report = self.metrics.classification_report(
                y_val_fold, y_pred, y_proba
            )
            
            fold_scores.append(fold_score)
            fold_reports.append(fold_report)
        
        return {
            'mean_accuracy': np.mean(fold_scores),
            'std_accuracy': np.std(fold_scores),
            'fold_reports': fold_reports
        }
```

### 2. Advanced Evaluation Metrics

```python
class VMDetectionMetrics:
    def __init__(self):
        self.class_names = ['clean', 'vmprotect', 'themida', 'custom_vm']
        
    def comprehensive_evaluation(self, y_true, y_pred, y_proba=None):
        """Calculate comprehensive evaluation metrics"""
        from sklearn.metrics import (
            accuracy_score, precision_recall_fscore_support,
            confusion_matrix, roc_auc_score, average_precision_score
        )
        
        # Basic metrics
        accuracy = accuracy_score(y_true, y_pred)
        precision, recall, f1, support = precision_recall_fscore_support(
            y_true, y_pred, average='weighted'
        )
        
        # Confusion matrix
        cm = confusion_matrix(y_true, y_pred)
        
        metrics = {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm.tolist(),
            'support': support.tolist()
        }
        
        # Probabilistic metrics if available
        if y_proba is not None:
            # Multi-class AUC
            try:
                auc_scores = []
                for i, class_name in enumerate(self.class_names):
                    y_true_binary = (y_true == i).astype(int)
                    y_score_binary = y_proba[:, i]
                    auc = roc_auc_score(y_true_binary, y_score_binary)
                    auc_scores.append(auc)
                
                metrics['auc_per_class'] = dict(zip(self.class_names, auc_scores))
                metrics['mean_auc'] = np.mean(auc_scores)
                
            except ValueError as e:
                print(f"Could not calculate AUC: {e}")
        
        return metrics
    
    def false_positive_analysis(self, y_true, y_pred, sample_paths):
        """Analyze false positive cases for model improvement"""
        false_positives = []
        
        for i, (true_label, pred_label) in enumerate(zip(y_true, y_pred)):
            if true_label == 0 and pred_label != 0:  # Clean sample predicted as VM
                false_positives.append({
                    'sample_path': sample_paths[i],
                    'true_label': self.class_names[true_label],
                    'predicted_label': self.class_names[pred_label],
                    'sample_index': i
                })
        
        return false_positives
    
    def generate_evaluation_report(self, results, output_path):
        """Generate comprehensive evaluation report"""
        import matplotlib.pyplot as plt
        import seaborn as sns
        
        # Create report
        report = f"""
# VM Detection Model Evaluation Report

## Overall Performance
- **Accuracy**: {results['accuracy']:.4f}
- **Precision**: {results['precision']:.4f}  
- **Recall**: {results['recall']:.4f}
- **F1 Score**: {results['f1_score']:.4f}

## Per-Class Performance
"""
        
        if 'auc_per_class' in results:
            report += "\n### AUC Scores\n"
            for class_name, auc in results['auc_per_class'].items():
                report += f"- **{class_name}**: {auc:.4f}\n"
        
        # Confusion matrix visualization
        plt.figure(figsize=(10, 8))
        sns.heatmap(
            results['confusion_matrix'], 
            annot=True, 
            fmt='d',
            xticklabels=self.class_names,
            yticklabels=self.class_names
        )
        plt.title('Confusion Matrix')
        plt.ylabel('True Label')
        plt.xlabel('Predicted Label')
        plt.savefig(f"{output_path}/confusion_matrix.png")
        plt.close()
        
        # Save report
        with open(f"{output_path}/evaluation_report.md", 'w') as f:
            f.write(report)
```

### 3. Robustness Testing

```python
class VMModelRobustnessTest:
    def __init__(self, model, feature_extractor):
        self.model = model
        self.feature_extractor = feature_extractor
        
    def adversarial_testing(self, test_samples, epsilon=0.01):
        """Test model robustness against adversarial examples"""
        robust_predictions = []
        
        for sample_path in test_samples:
            # Extract original features
            original_features = self.feature_extractor.extract_features(sample_path)
            original_pred = self.model.predict([original_features])[0]
            
            # Generate adversarial features
            adversarial_features = self._generate_adversarial_features(
                original_features, epsilon
            )
            adversarial_pred = self.model.predict([adversarial_features])[0]
            
            robust_predictions.append({
                'sample': sample_path,
                'original_prediction': original_pred,
                'adversarial_prediction': adversarial_pred,
                'robust': original_pred == adversarial_pred
            })
        
        return robust_predictions
    
    def _generate_adversarial_features(self, features, epsilon):
        """Generate adversarial features using FGSM-like approach"""
        # Add small random noise to features
        noise = np.random.normal(0, epsilon, size=features.shape)
        return features + noise
```

## Integration with Pattern Database

### 1. Model Deployment Integration

```python
from dragonslayer.core.model_registry import ModelRegistry
from dragonslayer.data.patterns import PatternDatabase

class VMModelIntegration:
    def __init__(self):
        self.model_registry = ModelRegistry()
        self.pattern_db = PatternDatabase()
        
    def register_trained_model(self, model, model_metadata):
        """Register trained model with the system"""
        
        # Model metadata
        metadata = {
            'model_id': model_metadata['model_id'],
            'model_type': model_metadata['architecture'],
            'training_date': datetime.now().isoformat(),
            'performance_metrics': model_metadata['validation_results'],
            'feature_requirements': model_metadata['feature_types'],
            'supported_architectures': ['x86', 'x64'],
            'confidence_threshold': 0.7
        }
        
        # Save model
        model_path = self.model_registry.save_model(model, metadata)
        
        # Update pattern database with model patterns
        self._extract_and_save_patterns(model, model_metadata)
        
        return model_path
    
    def _extract_and_save_patterns(self, model, metadata):
        """Extract interpretable patterns from trained model"""
        
        if hasattr(model, 'feature_importances_'):
            # For tree-based models, extract feature importance patterns
            important_features = self._get_important_features(
                model.feature_importances_, 
                metadata['feature_names']
            )
            
            for feature_name, importance in important_features:
                pattern = {
                    'pattern_id': f"ml_{metadata['model_id']}_{feature_name}",
                    'pattern_type': 'ml_feature',
                    'importance': importance,
                    'feature_name': feature_name,
                    'model_source': metadata['model_id']
                }
                self.pattern_db.add_pattern(pattern)
        
        elif hasattr(model, 'get_attention_weights'):
            # For transformer models, extract attention patterns
            attention_patterns = model.get_attention_weights()
            self._save_attention_patterns(attention_patterns, metadata)
    
    def create_runtime_classifier(self, model_id):
        """Create runtime classifier for integration with analysis pipeline"""
        
        class RuntimeVMClassifier:
            def __init__(self, model_path, metadata):
                self.model = self._load_model(model_path)
                self.metadata = metadata
                self.feature_extractor = self._create_feature_extractor(metadata)
                
            def classify_binary(self, binary_data):
                """Classify binary using trained model"""
                # Extract features
                features = self.feature_extractor.extract_features(binary_data)
                
                # Predict
                prediction = self.model.predict([features])[0]
                confidence = self.model.predict_proba([features])[0].max()
                
                return {
                    'prediction': prediction,
                    'confidence': confidence,
                    'vm_type': self.metadata['class_names'][prediction],
                    'model_id': self.metadata['model_id']
                }
            
            def _load_model(self, model_path):
                # Load serialized model
                import joblib
                return joblib.load(model_path)
                
            def _create_feature_extractor(self, metadata):
                # Create feature extractor based on model requirements
                from dragonslayer.ml.extractors import FeatureExtractorFactory
                return FeatureExtractorFactory.create(metadata['feature_requirements'])
        
        # Load model metadata
        metadata = self.model_registry.get_model_metadata(model_id)
        model_path = self.model_registry.get_model_path(model_id)
        
        return RuntimeVMClassifier(model_path, metadata)
```

### 2. Pattern Database Updates

```python
class ModelPatternExtractor:
    def __init__(self, pattern_database):
        self.pattern_db = pattern_database
        
    def extract_decision_tree_patterns(self, tree_model, feature_names):
        """Extract interpretable patterns from decision tree models"""
        from sklearn.tree import export_text
        
        tree_rules = export_text(tree_model, feature_names=feature_names)
        
        # Parse tree rules into patterns
        patterns = []
        for rule_line in tree_rules.split('\n'):
            if '<==' in rule_line or '>' in rule_line:
                pattern = self._parse_tree_rule(rule_line, feature_names)
                if pattern:
                    patterns.append(pattern)
        
        return patterns
    
    def _parse_tree_rule(self, rule_line, feature_names):
        """Parse individual tree rule into pattern format"""
        # Example: "  |--- opcode_mov <= 0.15"
        parts = rule_line.strip().split()
        if len(parts) >= 3:
            feature = parts[1]
            operator = parts[2]
            value = float(parts[3])
            
            return {
                'pattern_type': 'decision_rule',
                'feature': feature,
                'operator': operator,
                'threshold': value,
                'source': 'trained_model'
            }
        return None
    
    def update_pattern_database(self, patterns, model_id):
        """Update pattern database with extracted patterns"""
        for pattern in patterns:
            pattern['model_source'] = model_id
            pattern['confidence'] = self._calculate_pattern_confidence(pattern)
            self.pattern_db.add_pattern(pattern)
```

## Advanced Topics

### 1. Ensemble Methods

```python
class VMEnsembleClassifier:
    def __init__(self, models):
        self.models = models
        self.weights = None
        
    def fit_ensemble_weights(self, X_val, y_val):
        """Optimize ensemble weights based on validation performance"""
        from scipy.optimize import minimize
        
        def ensemble_loss(weights):
            weights = weights / np.sum(weights)  # Normalize
            ensemble_pred = self._weighted_predict(X_val, weights)
            return -accuracy_score(y_val, ensemble_pred)
        
        # Initialize equal weights
        initial_weights = np.ones(len(self.models)) / len(self.models)
        
        # Optimize weights
        result = minimize(ensemble_loss, initial_weights, method='SLSQP',
                         bounds=[(0, 1)] * len(self.models),
                         constraints={'type': 'eq', 'fun': lambda w: np.sum(w) - 1})
        
        self.weights = result.x
        
    def _weighted_predict(self, X, weights):
        """Make weighted ensemble predictions"""
        predictions = np.array([model.predict_proba(X) for model in self.models])
        weighted_pred = np.average(predictions, weights=weights, axis=0)
        return np.argmax(weighted_pred, axis=1)
    
    def predict(self, X):
        """Predict using ensemble"""
        if self.weights is None:
            # Equal weighting
            self.weights = np.ones(len(self.models)) / len(self.models)
        
        return self._weighted_predict(X, self.weights)
```

### 2. Model Interpretability

```python
import shap
from dragonslayer.ml.explainability import VMModelExplainer

class VMModelExplainer:
    def __init__(self, model, feature_names):
        self.model = model
        self.feature_names = feature_names
        
    def explain_predictions(self, X_sample, sample_names=None):
        """Generate explanations for model predictions"""
        
        # SHAP explanations
        explainer = shap.TreeExplainer(self.model)
        shap_values = explainer.shap_values(X_sample)
        
        explanations = []
        for i, (sample, shap_vals) in enumerate(zip(X_sample, shap_values)):
            
            # Get top contributing features
            feature_contributions = list(zip(self.feature_names, shap_vals))
            feature_contributions.sort(key=lambda x: abs(x[1]), reverse=True)
            
            top_features = feature_contributions[:10]
            
            explanation = {
                'sample_id': sample_names[i] if sample_names else f"sample_{i}",
                'prediction': self.model.predict([sample])[0],
                'confidence': self.model.predict_proba([sample])[0].max(),
                'top_features': [
                    {
                        'feature': feature,
                        'contribution': float(contribution),
                        'direction': 'positive' if contribution > 0 else 'negative'
                    }
                    for feature, contribution in top_features
                ]
            }
            
            explanations.append(explanation)
        
        return explanations
    
    def generate_feature_importance_report(self, output_path):
        """Generate feature importance visualization"""
        import matplotlib.pyplot as plt
        
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            
            # Create importance plot
            sorted_idx = np.argsort(importances)[::-1][:20]  # Top 20 features
            
            plt.figure(figsize=(12, 8))
            plt.bar(range(len(sorted_idx)), importances[sorted_idx])
            plt.xticks(range(len(sorted_idx)), 
                      [self.feature_names[i] for i in sorted_idx], 
                      rotation=45, ha='right')
            plt.title('Top 20 Feature Importances')
            plt.ylabel('Importance')
            plt.tight_layout()
            plt.savefig(f"{output_path}/feature_importance.png", dpi=300)
            plt.close()
```

### 3. Continuous Learning

```python
class ContinuousLearningPipeline:
    def __init__(self, base_model, update_threshold=100):
        self.base_model = base_model
        self.update_threshold = update_threshold  # Minimum samples before update
        self.new_samples = []
        self.new_labels = []
        
    def add_feedback_sample(self, sample, true_label, predicted_label):
        """Add feedback sample for model improvement"""
        # Only add misclassified samples for retraining
        if true_label != predicted_label:
            self.new_samples.append(sample)
            self.new_labels.append(true_label)
            
            # Trigger update if threshold reached
            if len(self.new_samples) >= self.update_threshold:
                self._update_model()
    
    def _update_model(self):
        """Incrementally update model with new samples"""
        print(f"Updating model with {len(self.new_samples)} new samples")
        
        # Incremental training (for supported models)
        if hasattr(self.base_model, 'partial_fit'):
            self.base_model.partial_fit(self.new_samples, self.new_labels)
        else:
            # Retrain with combined data (requires access to original training data)
            print("Model doesn't support incremental learning, full retraining needed")
        
        # Clear accumulated samples
        self.new_samples = []
        self.new_labels = []
```

## Troubleshooting

### Common Issues and Solutions

#### 1. Low Model Performance

**Symptoms**: Accuracy below 70%, high false positive rate

**Possible Causes**:
- Insufficient training data
- Poor feature engineering
- Data imbalance
- Overfitting

**Solutions**:
```python
# Check data balance
from collections import Counter
label_counts = Counter(y_train)
print(f"Label distribution: {label_counts}")

# Address imbalance
from imblearn.over_sampling import SMOTE
smote = SMOTE(random_state=42)
X_balanced, y_balanced = smote.fit_resample(X_train, y_train)

# Feature selection
from sklearn.feature_selection import SelectKBest, f_classif
selector = SelectKBest(f_classif, k=500)
X_selected = selector.fit_transform(X_train, y_train)

# Regularization for overfitting
from sklearn.linear_model import LogisticRegression
model = LogisticRegression(C=0.1, penalty='l2')  # Strong regularization
```

#### 2. Model Fails to Generalize

**Symptoms**: High training accuracy, low validation accuracy

**Solutions**:
```python
# Increase validation set diversity
def create_diverse_validation_set(samples, labels):
    # Stratify by multiple criteria
    from sklearn.model_selection import train_test_split
    
    # Split ensuring diversity in file sizes, compilers, etc.
    diverse_indices = stratified_diverse_split(samples, labels)
    return diverse_indices

# Add regularization
model_params = {
    'max_depth': 10,        # Limit tree depth
    'min_samples_split': 10, # Require more samples per split
    'max_features': 'sqrt'   # Random feature subset
}

# Cross-validation with time-based splits
def temporal_split(samples, labels, test_date):
    """Split based on sample collection date"""
    train_indices = [i for i, sample in enumerate(samples) 
                    if sample.collection_date < test_date]
    test_indices = [i for i, sample in enumerate(samples) 
                   if sample.collection_date >= test_date]
    return train_indices, test_indices
```

#### 3. High False Positive Rate on Clean Samples

**Symptoms**: Clean binaries incorrectly classified as VM-protected

**Solutions**:
```python
# Analyze false positives
def analyze_false_positives(model, X_test, y_test, sample_paths):
    y_pred = model.predict(X_test)
    
    false_positives = []
    for i, (true, pred, path) in enumerate(zip(y_test, y_pred, sample_paths)):
        if true == 0 and pred != 0:  # Clean sample predicted as VM
            false_positives.append((i, path))
    
    # Extract common characteristics
    fp_features = X_test[false_positives]
    common_patterns = analyze_common_features(fp_features)
    
    return common_patterns

# Adjust decision threshold
from sklearn.metrics import precision_recall_curve

def optimize_threshold(model, X_val, y_val):
    y_scores = model.predict_proba(X_val)[:, 1]
    precision, recall, thresholds = precision_recall_curve(y_val, y_scores)
    
    # Find threshold that maximizes F1 score
    f1_scores = 2 * (precision * recall) / (precision + recall)
    optimal_idx = np.argmax(f1_scores)
    optimal_threshold = thresholds[optimal_idx]
    
    return optimal_threshold

# Use cost-sensitive learning
from sklearn.ensemble import RandomForestClassifier

# Penalize false positives more heavily
class_weights = {0: 1.0, 1: 2.0}  # Higher cost for misclassifying VM samples
model = RandomForestClassifier(class_weight=class_weights)
```

#### 4. Model Training Takes Too Long

**Symptoms**: Training time exceeds acceptable limits

**Solutions**:
```python
# Feature selection for dimensionality reduction
from sklearn.feature_selection import SelectFromModel
from sklearn.ensemble import ExtraTreesClassifier

# Use extremely randomized trees for feature selection
selector = SelectFromModel(ExtraTreesClassifier(n_estimators=50))
X_selected = selector.fit_transform(X_train, y_train)

# Parallel processing
from sklearn.ensemble import RandomForestClassifier
model = RandomForestClassifier(n_jobs=-1)  # Use all CPU cores

# Incremental learning for large datasets
from sklearn.linear_model import SGDClassifier
model = SGDClassifier()

# Train in batches
batch_size = 1000
for i in range(0, len(X_train), batch_size):
    X_batch = X_train[i:i+batch_size]
    y_batch = y_train[i:i+batch_size]
    model.partial_fit(X_batch, y_batch, classes=np.unique(y_train))
```

### Performance Monitoring

```python
class ModelPerformanceMonitor:
    def __init__(self, model_id):
        self.model_id = model_id
        self.performance_history = []
        
    def log_prediction(self, prediction, ground_truth, confidence):
        """Log individual prediction for monitoring"""
        self.performance_history.append({
            'timestamp': datetime.now(),
            'prediction': prediction,
            'ground_truth': ground_truth,
            'correct': prediction == ground_truth,
            'confidence': confidence
        })
    
    def calculate_drift_metrics(self, window_size=100):
        """Calculate concept drift metrics"""
        if len(self.performance_history) < window_size * 2:
            return None
        
        recent_performance = self.performance_history[-window_size:]
        previous_performance = self.performance_history[-window_size*2:-window_size]
        
        recent_accuracy = np.mean([p['correct'] for p in recent_performance])
        previous_accuracy = np.mean([p['correct'] for p in previous_performance])
        
        drift_magnitude = abs(recent_accuracy - previous_accuracy)
        
        return {
            'recent_accuracy': recent_accuracy,
            'previous_accuracy': previous_accuracy,
            'drift_magnitude': drift_magnitude,
            'needs_retraining': drift_magnitude > 0.05  # 5% threshold
        }
```

---

This comprehensive guide provides the foundation for creating, training, and deploying custom VM detection models within the VMDragonSlayer ecosystem. For additional support or advanced use cases, consult the API documentation and community resources.
