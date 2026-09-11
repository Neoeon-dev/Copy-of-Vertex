"""
VERTEX ML Inference Models Package.
Exposes forensic tabular inference service, prediction dataclasses, and model registries.
"""
from app.ml.models.forensic_service import (
    ForensicPrediction,
    ForensicTabularService,
    get_forensic_service,
)

__all__ = [
    "ForensicPrediction",
    "ForensicTabularService",
    "get_forensic_service",
]
