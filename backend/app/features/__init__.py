"""
VERTEX Forensic Feature Engineering Engine.
Provides deterministic, auditable, and versioned feature extraction across 11 forensic signal groups.
"""
from app.features.version import FORENSIC_FEATURE_VERSION, FEATURE_EXTRACTOR_VERSION
from app.features.schema import (
    FeatureType,
    FeatureDefinition,
    FeatureVector,
    SPF_RESULT_ENCODING,
    DKIM_RESULT_ENCODING,
    DMARC_RESULT_ENCODING,
    DMARC_POLICY_ENCODING,
    ALIGNMENT_ENCODING,
    IP_VERSION_ENCODING,
)
from app.features.registry import (
    FEATURE_REGISTRY,
    get_feature_registry,
    get_feature_names,
    get_feature_by_name,
    get_features_by_group,
    export_feature_schema_json,
)
from app.features.validators import validate_feature_vector, validate_features_dict
from app.features.extractor import ForensicFeatureExtractor

__all__ = [
    "FORENSIC_FEATURE_VERSION",
    "FEATURE_EXTRACTOR_VERSION",
    "FeatureType",
    "FeatureDefinition",
    "FeatureVector",
    "SPF_RESULT_ENCODING",
    "DKIM_RESULT_ENCODING",
    "DMARC_RESULT_ENCODING",
    "DMARC_POLICY_ENCODING",
    "ALIGNMENT_ENCODING",
    "IP_VERSION_ENCODING",
    "FEATURE_REGISTRY",
    "get_feature_registry",
    "get_feature_names",
    "get_feature_by_name",
    "get_features_by_group",
    "export_feature_schema_json",
    "validate_feature_vector",
    "validate_features_dict",
    "ForensicFeatureExtractor",
]
