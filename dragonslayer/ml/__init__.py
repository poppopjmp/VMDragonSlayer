"""
Machine Learning Module

All imports are guarded so the package can be imported even when
optional dependencies (scikit-learn, PyTorch, etc.) are missing.
"""

try:
    from .pipeline import (
        EXTENDED_FEATURE_NAMES,
        VMPROTECT_BIGRAMS,
        FeatureExtractor,
        FeatureVector,
        extract_bigram_features,
        extract_extended_features,
        extract_operand_pattern_features,
        extract_register_effects,
    )
except (ImportError, AttributeError):
    FeatureExtractor = None  # type: ignore[assignment,misc]
    FeatureVector = None  # type: ignore[assignment,misc]
    extract_extended_features = None  # type: ignore[assignment]
    extract_bigram_features = None  # type: ignore[assignment]
    extract_register_effects = None  # type: ignore[assignment]
    extract_operand_pattern_features = None  # type: ignore[assignment]
    EXTENDED_FEATURE_NAMES = None  # type: ignore[assignment]
    VMPROTECT_BIGRAMS = None  # type: ignore[assignment]

try:
    from .trainer import (
        PROTECTOR_CV,
        PROTECTOR_THEMIDA,
        PROTECTOR_VMPROTECT,
        ModelTrainer,
        TrainingResult,
        feature_importance,
        generate_multi_protector_data,
        generate_synthetic_handlers,
        prepare_extended_training_data,
        prepare_training_data,
        train_and_save_model,
        train_full_pipeline,
    )
except (ImportError, AttributeError):
    ModelTrainer = None  # type: ignore[assignment,misc]
    TrainingResult = None  # type: ignore[assignment,misc]
    prepare_training_data = None  # type: ignore[assignment]
    prepare_extended_training_data = None  # type: ignore[assignment]
    generate_synthetic_handlers = None  # type: ignore[assignment]
    generate_multi_protector_data = None  # type: ignore[assignment]
    feature_importance = None  # type: ignore[assignment]
    train_full_pipeline = None  # type: ignore[assignment]
    train_and_save_model = None  # type: ignore[assignment]
    PROTECTOR_VMPROTECT = None  # type: ignore[assignment]
    PROTECTOR_THEMIDA = None  # type: ignore[assignment]
    PROTECTOR_CV = None  # type: ignore[assignment]

try:
    from .model import (
        BaseModel,
        PredictionResult,
        SymbolicClassifierModel,
        VMHandlerModel,
    )
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
    CANONICAL_CATEGORIES = None  # type: ignore[assignment]
    CANONICAL_SET = None  # type: ignore[assignment]
    canonicalize = None  # type: ignore[assignment]
    is_canonical = None  # type: ignore[assignment]

try:
    from .evaluate import (
        ClassMetrics,
        EvaluationReport,
        GroundTruthEntry,
        evaluate_model,
        load_ground_truth,
    )
except (ImportError, AttributeError):
    EvaluationReport = None  # type: ignore[assignment,misc]
    GroundTruthEntry = None  # type: ignore[assignment,misc]
    ClassMetrics = None  # type: ignore[assignment,misc]
    evaluate_model = None  # type: ignore[assignment]
    load_ground_truth = None  # type: ignore[assignment]

try:
    from .ensemble import EnsembleClassifier, StackedEnsemble, WeightedEnsemble
except (ImportError, AttributeError):
    EnsembleClassifier = None  # type: ignore[assignment,misc]
    WeightedEnsemble = None  # type: ignore[assignment,misc]
    StackedEnsemble = None  # type: ignore[assignment,misc]

try:
    from .classifier import FeatureExplainer, VMClassifier
except (ImportError, AttributeError):
    VMClassifier = None  # type: ignore[assignment,misc]
    FeatureExplainer = None  # type: ignore[assignment,misc]

try:
    from .handler_classifier import (
        HANDLER_CATEGORIES,
        TrainedHandlerModel,
        build_handler_classifier,
        classify_handlers,
    )
except (ImportError, AttributeError):
    TrainedHandlerModel = None  # type: ignore[assignment,misc]
    classify_handlers = None  # type: ignore[assignment]
    build_handler_classifier = None  # type: ignore[assignment]
    HANDLER_CATEGORIES = None  # type: ignore[assignment]

try:
    from .active_learning import (
        FeedbackEntry,
        FeedbackStore,
        UncertainSample,
        UncertaintyStrategy,
        compute_entropy,
        compute_margin,
        export_training_set,
        select_uncertain_samples,
    )
except (ImportError, AttributeError):
    UncertainSample = None  # type: ignore[assignment,misc]
    UncertaintyStrategy = None  # type: ignore[assignment,misc]
    FeedbackStore = None  # type: ignore[assignment,misc]
    FeedbackEntry = None  # type: ignore[assignment,misc]
    select_uncertain_samples = None  # type: ignore[assignment]
    compute_entropy = None  # type: ignore[assignment]
    compute_margin = None  # type: ignore[assignment]
    export_training_set = None  # type: ignore[assignment]

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
    'generate_multi_protector_data',
    'feature_importance',
    'train_full_pipeline',
    'train_and_save_model',
    'PROTECTOR_VMPROTECT',
    'PROTECTOR_THEMIDA',
    'PROTECTOR_CV',
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
    'UncertainSample',
    'UncertaintyStrategy',
    'FeedbackStore',
    'FeedbackEntry',
    'select_uncertain_samples',
    'compute_entropy',
    'compute_margin',
    'export_training_set',
]
