"""
Phase D3 Semantic NLP Package for VERTEX.
Provides text-only semantic feature extraction, baseline, transformer fine-tuning, calibration, and inference.
"""
from app.ml.semantic.preprocessor import EmailTextPreprocessor, SEMANTIC_PREPROCESSING_VERSION
from app.ml.semantic.tokenizer import (
    load_semantic_tokenizer,
    analyze_sequence_lengths,
    TOKENIZER_VERSION,
    TOKENIZER_NAME,
)
from app.ml.semantic.baseline import TfidfLogisticBaseline
from app.ml.semantic.dataset import EmailTextDataset, compute_class_weights_tensor
from app.ml.semantic.trainer import SemanticTransformerTrainer
from app.ml.semantic.calibrator import TemperatureScalingCalibrator, compute_ece
from app.ml.semantic.evaluator import (
    evaluate_predictions,
    evaluate_short_text_robustness,
    evaluate_source_generalization,
    analyze_model_errors,
)
from app.ml.semantic.robustness import (
    run_subject_body_ablation,
    run_text_perturbation_tests,
    test_d2_1_failure_reproduction,
)
from app.ml.semantic.service import SemanticInferenceService, SEMANTIC_MODEL_VERSION

__all__ = [
    "EmailTextPreprocessor",
    "SEMANTIC_PREPROCESSING_VERSION",
    "load_semantic_tokenizer",
    "analyze_sequence_lengths",
    "TOKENIZER_VERSION",
    "TOKENIZER_NAME",
    "TfidfLogisticBaseline",
    "EmailTextDataset",
    "compute_class_weights_tensor",
    "SemanticTransformerTrainer",
    "TemperatureScalingCalibrator",
    "compute_ece",
    "evaluate_predictions",
    "evaluate_short_text_robustness",
    "evaluate_source_generalization",
    "analyze_model_errors",
    "run_subject_body_ablation",
    "run_text_perturbation_tests",
    "test_d2_1_failure_reproduction",
    "SemanticInferenceService",
    "SEMANTIC_MODEL_VERSION",
]
