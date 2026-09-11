"""
Forensic Feature Schema & Type Definitions for VERTEX.
Provides strict type contracts, deterministic missing-value policies,
categorical integer encodings, and clear separation between metadata and ML signals.
"""
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, Any, List, Optional, Union
import math

from app.features.version import FORENSIC_FEATURE_VERSION, FEATURE_EXTRACTOR_VERSION


class FeatureType(str, Enum):
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    CATEGORICAL = "categorical"


# ── Stable Numeric Encodings for Categorical Forensic Signals ─────────────────

SPF_RESULT_ENCODING = {
    "unknown": -1.0,
    "none": 0.0,
    "pass": 1.0,
    "neutral": 2.0,
    "softfail": 3.0,
    "fail": 4.0,
    "temperror": 5.0,
    "permerror": 6.0,
}

DKIM_RESULT_ENCODING = {
    "unknown": -1.0,
    "none": 0.0,
    "pass": 1.0,
    "neutral": 2.0,
    "fail": 3.0,
    "temperror": 4.0,
    "permerror": 5.0,
}

DMARC_RESULT_ENCODING = {
    "unknown": -1.0,
    "none": 0.0,
    "pass": 1.0,
    "fail": 2.0,
    "temperror": 3.0,
    "permerror": 4.0,
}

DMARC_POLICY_ENCODING = {
    "unknown": -1.0,
    "none": 0.0,
    "quarantine": 1.0,
    "reject": 2.0,
}

ALIGNMENT_ENCODING = {
    "unknown": -1.0,
    "none": 0.0,
    "fail": 1.0,
    "relaxed_pass": 2.0,
    "strict_pass": 3.0,
}

IP_VERSION_ENCODING = {
    "none": 0.0,
    "ipv4": 4.0,
    "ipv6": 6.0,
}


@dataclass
class FeatureDefinition:
    """Metadata describing a single forensic feature in the registry."""
    name: str
    group: str
    dtype: FeatureType
    description: str
    source: str
    extraction_function: str
    default_value: float
    version: str = FORENSIC_FEATURE_VERSION
    requires_raw_email: bool = False
    requires_network: bool = False
    safe_for_ml: bool = True
    forensic_rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "group": self.group,
            "dtype": self.dtype.value,
            "description": self.description,
            "source": self.source,
            "extraction_function": self.extraction_function,
            "default_value": self.default_value,
            "version": self.version,
            "requires_raw_email": self.requires_raw_email,
            "requires_network": self.requires_network,
            "safe_for_ml": self.safe_for_ml,
            "forensic_rationale": self.forensic_rationale,
        }


@dataclass
class FeatureVector:
    """Complete forensic feature vector containing metadata and ML-ready features."""
    record_id: str
    source_dataset: str
    normalized_label: Optional[str]
    threat_type: Optional[str]
    raw_evidence_available: bool
    feature_version: str = FORENSIC_FEATURE_VERSION
    extractor_version: str = FEATURE_EXTRACTOR_VERSION
    features: Dict[str, float] = field(default_factory=dict)
    explanations: Dict[str, str] = field(default_factory=dict)

    def to_flat_dict(self) -> Dict[str, Any]:
        """Flattens metadata and features into a single dict for Parquet serialization."""
        res: Dict[str, Any] = {
            "record_id": self.record_id,
            "source_dataset": self.source_dataset,
            "normalized_label": self.normalized_label,
            "threat_type": self.threat_type,
            "raw_evidence_available": 1.0 if self.raw_evidence_available else 0.0,
            "feature_version": self.feature_version,
            "extractor_version": self.extractor_version,
        }
        res.update(self.features)
        return res

    def get_features_only(self) -> Dict[str, float]:
        """Returns exclusively the numeric ML features, strictly excluding target metadata."""
        return dict(self.features)
