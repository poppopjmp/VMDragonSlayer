"""
Machine Learning Module

All imports are guarded so the package can be imported even when
optional dependencies (scikit-learn, PyTorch, etc.) are missing.
"""

try:
    from .pipeline import (
        FeatureExtractor,
        FeatureVector,
        extract_extended_features,
        extract_bigram_features,
        extract_register_effects,
        extract_operand_pattern_features,
        EXTENDED_FEATURE_NAMES,
        VMPROTECT_BIGRAMS,
    )
except (ImportError, AttributeError):
    FeatureExtractor = None  # type: ignore[assignment,misc]
    FeatureVector = None  # type: ignore[assignment,misc]
    extract_extended_features = None  # type: ignore[assignment,misc]
    extract_bigram_features = None  # type: ignore[assignment,misc]
    extract_register_effects = None  # type: ignore[assignment,misc]
    extract_operand_pattern_features = None  # type: ignore[assignment,misc]
    EXTENDED_FEATURE_NAMES = None  # type: ignore[assignment,misc]
    VMPROTECT_BIGRAMS = None  # type: ignore[assignment,misc]

try:
    from .trainer import (
        ModelTrainer,
        TrainingResult,
        prepare_training_data,
        prepare_extended_training_data,
        generate_synthetic_handlers,
        feature_importance,
        train_full_pipeline,
    )
except (ImportError, AttributeError):
    ModelTrainer = None  # type: ignore[assignment,misc]
    TrainingResult = None  # type: ignore[assignment,misc]
    prepare_training_data = None  # type: ignore[assignment,misc]
    prepare_extended_training_data = None  # type: ignore[assignment,misc]
    generate_synthetic_handlers = None  # type: ignore[assignment,misc]
    feature_importance = None  # type: ignore[assignment,misc]
    train_full_pipeline = None  # type: ignore[assignment,misc]

try:
    from .model import BaseModel, VMHandlerModel, PredictionResult, SymbolicClassifierModel
except (ImportError, AttributeError):
    BaseModel = None  # type: ignore[assignment,misc]
    VMHandlerModel = None  # type: ignore[assignment,misc]
    PredictionResult = None  # type: ignore[assignment,misc]
    SymbolicClassifierModel = None  # type: ignore[assignment,misc]

try:
    from .taxonomy import (
        CANONICAL_CATEGORIES,
        CANONICAL_SET,
        canonicalize,
        is_canonical,
    )
except (ImportError, AttributeError):
    CANONICAL_CATEGORIES = None  # type: ignore[assignment,misc]
    CANONICAL_SET = None  # type: ignore[assignment,misc]
    canonicalize = None  # type: ignore[assignment,misc]
    is_canonical = None  # type: ignore[assignment,misc]

try:
    from .evaluate import (
        EvaluationReport,
        GroundTruthEntry,
        ClassMetrics,
        evaluate_model,
        load_ground_truth,
    )
except (ImportError, AttributeError):
    EvaluationReport = None  # type: ignore[assignment,misc]
    GroundTruthEntry = None  # type: ignore[assignment,misc]
    ClassMetrics = None  # type: ignore[assignment,misc]
    evaluate_model = None  # type: ignore[assignment,misc]
    load_ground_truth = None  # type: ignore[assignment,misc]

try:
    from .ensemble import EnsembleClassifier, WeightedEnsemble, StackedEnsemble
except (ImportError, AttributeError):
    EnsembleClassifier = None  # type: ignore[assignment,misc]
    WeightedEnsemble = None  # type: ignore[assignment,misc]
    StackedEnsemble = None  # type: ignore[assignment,misc]

try:
    from .classifier import VMClassifier, FeatureExplainer
except (ImportError, AttributeError):
    VMClassifier = None  # type: ignore[assignment,misc]
    FeatureExplainer = None  # type: ignore[assignment,misc]

try:
    from .handler_classifier import (
        TrainedHandlerModel,
        classify_handlers,
        build_handler_classifier,
        HANDLER_CATEGORIES,
    )
except (ImportError, AttributeError):
    TrainedHandlerModel = None  # type: ignore[assignment,misc]
    classify_handlers = None  # type: ignore[assignment,misc]
    build_handler_classifier = None  # type: ignore[assignment,misc]
    HANDLER_CATEGORIES = None  # type: ignore[assignment,misc]

__all__ = [
    'FeatureExtractor',
    'FeatureVector',
    'extract_extended_features',
    'extract_bigram_features',
    'extract_register_effects',
    'extract_operand_pattern_features',
    'EXTENDED_FEATURE_NAMES',
    'VMPROTECT_BIGRAMS',
    'ModelTrainer',
    'TrainingResult',
    'prepare_training_data',
    'prepare_extended_training_data',
    'generate_synthetic_handlers',
    'feature_importance',
    'train_full_pipeline',
    'BaseModel',
    'VMHandlerModel',
    'PredictionResult',
    'SymbolicClassifierModel',
    'CANONICAL_CATEGORIES',
    'CANONICAL_SET',
    'canonicalize',
    'is_canonical',
    'EvaluationReport',
    'GroundTruthEntry',
    'ClassMetrics',
    'evaluate_model',
    'load_ground_truth',
    'EnsembleClassifier',
    'WeightedEnsemble',
    'StackedEnsemble',
    'VMClassifier',
    'FeatureExplainer',
    'TrainedHandlerModel',
    'classify_handlers',
    'build_handler_classifier',
    'HANDLER_CATEGORIES',
]
