"""
Model versioning and label contracts for VERTEX ML models.
"""
from typing import Dict, List

FORENSIC_MODEL_VERSION = "1.0.0"

LABEL_TO_INT: Dict[str, int] = {
    "legitimate": 0,
    "spam": 1,
    "phishing": 2,
}

INT_TO_LABEL: Dict[int, str] = {
    0: "legitimate",
    1: "spam",
    2: "phishing",
}

TARGET_CLASSES: List[str] = ["legitimate", "spam", "phishing"]
