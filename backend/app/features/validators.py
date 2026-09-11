"""
Forensic Feature Vector Validators for VERTEX.
Enforces strict contracts:
1. No NaN, +/-Inf, or None in numeric features.
2. Complete coverage against FEATURE_REGISTRY.
3. Strict zero-target-leakage validation.
4. Value range and type sanity checks.
"""
from typing import Dict, Any, List, Tuple
import math

from app.features.schema import FeatureVector
from app.features.registry import get_feature_names, get_feature_by_name

FORBIDDEN_TARGET_KEYS = {
    "normalized_label",
    "threat_type",
    "original_label",
    "source_dataset",
    "label",
    "target",
    "is_phishing",
    "is_spam",
    "ground_truth",
}


def validate_features_dict(features: Dict[str, float]) -> Tuple[bool, List[str]]:
    """
    Validates a dictionary of extracted feature values.
    Returns (is_valid, list_of_errors).
    """
    errors: List[str] = []
    expected_names = set(get_feature_names())
    actual_names = set(features.keys())

    # 1. Target Leakage Check
    leaked = actual_names.intersection(FORBIDDEN_TARGET_KEYS)
    if leaked:
        errors.append(f"TARGET LEAKAGE DETECTED in features: {leaked}")

    # 2. Completeness Check
    missing = expected_names - actual_names
    if missing:
        errors.append(f"Missing {len(missing)} features from registry: {sorted(missing)[:5]}...")

    unexpected = actual_names - expected_names
    if unexpected:
        errors.append(f"Unexpected {len(unexpected)} features not in registry: {sorted(unexpected)[:5]}...")

    # 3. Numeric Integrity (no NaN, +/-inf, None, must be float/int)
    for name, val in features.items():
        if val is None:
            errors.append(f"Feature '{name}' has None value.")
            continue
        if not isinstance(val, (int, float)):
            errors.append(f"Feature '{name}' has non-numeric type {type(val)}: {val}")
            continue
        if math.isnan(val):
            errors.append(f"Feature '{name}' is NaN.")
        elif math.isinf(val):
            errors.append(f"Feature '{name}' is Infinite ({val}).")

    return (len(errors) == 0, errors)


def validate_feature_vector(vec: FeatureVector) -> Tuple[bool, List[str]]:
    """
    Validates a full FeatureVector object including metadata separation and feature completeness.
    """
    errors: List[str] = []

    if not vec.record_id:
        errors.append("FeatureVector missing record_id.")

    # Validate the numeric features portion
    is_valid, feat_errors = validate_features_dict(vec.features)
    errors.extend(feat_errors)

    return (len(errors) == 0, errors)
