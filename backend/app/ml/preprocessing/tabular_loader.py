"""
Dataset loader for VERTEX Forensic Tabular ML.
Loads feature parquet files, enforces strict schema adherence and canonical feature ordering,
and guarantees zero target leakage.
"""
from typing import Tuple, List, Dict, Any, Optional
from dataclasses import dataclass
import os
import numpy as np
import pyarrow.parquet as pq

from app.features.registry import get_feature_names
from app.features.validators import FORBIDDEN_TARGET_KEYS
from app.ml.version import LABEL_TO_INT, TARGET_CLASSES


@dataclass
class TabularDataset:
    """Container holding feature matrix, label targets, and isolated metadata."""
    X: np.ndarray
    y: np.ndarray
    feature_names: List[str]
    record_ids: List[str]
    source_datasets: List[str]
    threat_types: List[Optional[str]]
    raw_evidence_available: List[float]
    normalized_labels: List[str]

    @property
    def num_samples(self) -> int:
        return len(self.y)

    @property
    def num_features(self) -> int:
        return self.X.shape[1] if self.X.ndim > 1 else 0


def load_tabular_parquet(
    parquet_path: str,
    feature_names: Optional[List[str]] = None,
    allow_missing_labels: bool = False,
) -> TabularDataset:
    """
    Loads feature parquet file and separates numeric features from metadata/targets.
    Asserts complete schema alignment, canonical ordering, and zero target leakage.
    """
    if not os.path.exists(parquet_path):
        raise FileNotFoundError(f"Feature dataset not found: {parquet_path}")

    expected_features = feature_names or get_feature_names()
    table = pq.read_table(parquet_path)
    available_cols = set(table.column_names)

    # 1. Leakage assertion
    leaked_cols = set(expected_features).intersection(FORBIDDEN_TARGET_KEYS)
    if leaked_cols:
        raise ValueError(f"FATAL: Target leakage in requested feature list: {leaked_cols}")

    # 2. Completeness assertion
    missing_cols = set(expected_features) - available_cols
    if missing_cols:
        raise ValueError(
            f"Feature dataset {parquet_path} is missing {len(missing_cols)} required features: "
            f"{sorted(missing_cols)[:5]}"
        )

    # 3. Extract metadata safely
    record_ids = table.column("record_id").to_pylist() if "record_id" in available_cols else []
    source_datasets = table.column("source_dataset").to_pylist() if "source_dataset" in available_cols else []
    threat_types = table.column("threat_type").to_pylist() if "threat_type" in available_cols else []
    raw_evidence = table.column("raw_evidence_available").to_pylist() if "raw_evidence_available" in available_cols else []
    raw_labels = table.column("normalized_label").to_pylist() if "normalized_label" in available_cols else []

    # Map labels to integer targets
    y_list: List[int] = []
    for idx, lbl in enumerate(raw_labels):
        if lbl in LABEL_TO_INT:
            y_list.append(LABEL_TO_INT[lbl])
        elif allow_missing_labels:
            y_list.append(-1)
        else:
            raise ValueError(f"Unknown or invalid label '{lbl}' at row {idx} in {parquet_path}")

    y = np.array(y_list, dtype=np.int64)

    # 4. Extract numeric feature matrix in exact canonical order
    arrays = []
    for fname in expected_features:
        col = table.column(fname).to_numpy()
        # Ensure float32 representation
        arrays.append(col.astype(np.float32))

    X = np.column_stack(arrays)

    # 5. Sanity checks: NaN / Inf checks
    if np.isnan(X).any():
        raise ValueError(f"NaN values detected in feature matrix loaded from {parquet_path}")
    if np.isinf(X).any():
        raise ValueError(f"Infinite values detected in feature matrix loaded from {parquet_path}")

    return TabularDataset(
        X=X,
        y=y,
        feature_names=list(expected_features),
        record_ids=record_ids,
        source_datasets=source_datasets,
        threat_types=threat_types,
        raw_evidence_available=raw_evidence,
        normalized_labels=raw_labels,
    )
