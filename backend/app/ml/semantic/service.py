"""
Production-grade Semantic Inference Service for Phase D3.
Provides isolated, thread-safe, text-only inference without dependencies on forensic features.
"""
from __future__ import annotations

import os
import json
from typing import Dict, Any, List, Optional, Tuple, Union
import numpy as np
import torch
from transformers import AutoModelForSequenceClassification, AutoTokenizer

from app.ml.semantic.preprocessor import EmailTextPreprocessor, SEMANTIC_PREPROCESSING_VERSION
from app.ml.semantic.calibrator import TemperatureScalingCalibrator
from app.ml.version import INT_TO_LABEL

SEMANTIC_MODEL_VERSION = "1.0.0"


class SemanticInferenceService:
    """
    Inference service for Phase D3 Semantic Transformer.
    """

    def __init__(
        self,
        model_dir: str,
        device: Optional[str] = None,
        max_length: int = 128,
    ) -> None:
        self.model_dir = model_dir
        self.max_length = max_length
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")

        # 1. Initialize preprocessor
        self.preprocessor = EmailTextPreprocessor()
        self.preprocessing_version = SEMANTIC_PREPROCESSING_VERSION

        # 2. Load tokenizer
        tokenizer_path = os.path.join(model_dir, "tokenizer")
        if os.path.exists(tokenizer_path):
            self.tokenizer = AutoTokenizer.from_pretrained(tokenizer_path)
        else:
            self.tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")

        # 3. Load model weights
        self.model = AutoModelForSequenceClassification.from_pretrained(model_dir)
        self.model.to(self.device)
        self.model.eval()

        # 4. Load calibrator if available
        cal_path = os.path.join(model_dir, "temperature.json")
        if os.path.exists(cal_path):
            self.calibrator = TemperatureScalingCalibrator.load(cal_path)
        else:
            self.calibrator = TemperatureScalingCalibrator(temperature=1.0)

        # 5. Load metadata
        meta_path = os.path.join(model_dir, "metadata.json")
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                self.metadata = json.load(f)
        else:
            self.metadata = {"model_version": SEMANTIC_MODEL_VERSION}

        self.model_version = self.metadata.get("model_version", SEMANTIC_MODEL_VERSION)

    def predict_email(
        self,
        subject: Optional[str],
        body: Optional[str],
    ) -> Dict[str, Any]:
        """
        Runs semantic inference on a single email.
        """
        res = self.predict_batch([(subject, body)])
        return res[0]

    def predict_batch(
        self,
        emails: List[Tuple[Optional[str], Optional[str]]],
        batch_size: int = 64,
    ) -> List[Dict[str, Any]]:
        """
        Runs batched semantic inference.
        """
        if not emails:
            return []

        # Format texts
        formatted_texts = [
            self.preprocessor.format_email(subj, body)
            for subj, body in emails
        ]

        all_probs = []
        with torch.no_grad():
            for i in range(0, len(formatted_texts), batch_size):
                batch_texts = formatted_texts[i : i + batch_size]
                inputs = self.tokenizer(
                    batch_texts,
                    padding=True,
                    truncation=True,
                    max_length=self.max_length,
                    return_tensors="pt",
                ).to(self.device)

                outputs = self.model(**inputs)
                logits = outputs.logits.cpu().numpy()

                # Apply calibration if fitted
                probs = self.calibrator.predict_proba(logits)
                all_probs.append(probs)

        probs_arr = np.vstack(all_probs)
        results = []

        for i in range(len(emails)):
            p = probs_arr[i]
            pred_idx = int(np.argmax(p))
            confidence = float(p[pred_idx])
            pred_class = INT_TO_LABEL.get(pred_idx, "unknown")

            results.append({
                "model_version": self.model_version,
                "preprocessing_version": self.preprocessing_version,
                "predicted_class": pred_class,
                "confidence": round(confidence, 4),
                "probabilities": {
                    "legitimate": round(float(p[0]), 4),
                    "spam": round(float(p[1]), 4),
                    "phishing": round(float(p[2]), 4),
                },
            })

        return results
