"""
Source Fingerprinting Diagnostic Engine for VERTEX ML.
Trains a diagnostic model to predict source_dataset from the 125 features,
evaluates whether features act as dataset fingerprints, and computes
threat-correlation vs source-correlation trade-offs.
"""
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import warnings
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.feature_selection import f_classif
from lightgbm import LGBMClassifier

from app.ml.preprocessing.tabular_loader import TabularDataset
from app.features.registry import get_feature_by_name


def train_source_classifier(
    train_ds: TabularDataset,
    val_ds: TabularDataset,
    test_ds: TabularDataset,
    n_estimators: int = 150,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Trains a diagnostic classifier to predict source_dataset from features.
    Diagnostic experiment ONLY - never part of the production threat model.
    """
    # Map sources to integers
    unique_sources = sorted(list(set(train_ds.source_datasets)))
    source_to_idx = {s: i for i, s in enumerate(unique_sources)}

    y_src_train = np.array([source_to_idx[s] for s in train_ds.source_datasets], dtype=np.int64)
    y_src_val = np.array([source_to_idx[s] for s in val_ds.source_datasets], dtype=np.int64)
    y_src_test = np.array([source_to_idx[s] for s in test_ds.source_datasets], dtype=np.int64)

    clf = LGBMClassifier(
        objective="multiclass",
        num_class=len(unique_sources),
        n_estimators=n_estimators,
        learning_rate=0.08,
        num_leaves=31,
        random_state=random_state,
        n_jobs=-1,
        verbose=-1,
    )

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore")
        clf.fit(train_ds.X, y_src_train)

    # Evaluate on val and test
    val_preds = clf.predict(val_ds.X)
    test_preds = clf.predict(test_ds.X)

    val_acc = float(round(accuracy_score(y_src_val, val_preds), 4))
    val_macro_f1 = float(round(precision_recall_fscore_support(y_src_val, val_preds, average="macro", zero_division=0)[2], 4))

    test_acc = float(round(accuracy_score(y_src_test, test_preds), 4))
    test_macro_f1 = float(round(precision_recall_fscore_support(y_src_test, test_preds, average="macro", zero_division=0)[2], 4))

    # Feature importance for source prediction
    gain_raw = clf.booster_.feature_importance(importance_type="gain")
    sorted_indices = np.argsort(gain_raw)[::-1]
    top_source_features = [
        {
            "feature": train_ds.feature_names[i],
            "group": getattr(get_feature_by_name(train_ds.feature_names[i]), "group", "unknown"),
            "source_predictive_gain": float(round(float(gain_raw[i]), 2)),
        }
        for i in sorted_indices[:20]
    ]

    return {
        "num_sources": len(unique_sources),
        "source_classes": unique_sources,
        "val_accuracy": val_acc,
        "val_macro_f1": val_macro_f1,
        "test_accuracy": test_acc,
        "test_macro_f1": test_macro_f1,
        "top_source_fingerprint_features": top_source_features,
    }


def compute_threat_vs_source_correlation(
    train_ds: TabularDataset,
) -> List[Dict[str, Any]]:
    """
    Computes ANOVA F-statistic of each feature with respect to Threat Label (y)
    versus Source Dataset (source_dataset).
    """
    unique_sources = sorted(list(set(train_ds.source_datasets)))
    source_to_idx = {s: i for i, s in enumerate(unique_sources)}
    y_src = np.array([source_to_idx[s] for s in train_ds.source_datasets], dtype=np.int64)

    # Compute ANOVA F-statistics
    f_threat, _ = f_classif(train_ds.X, train_ds.y)
    f_source, _ = f_classif(train_ds.X, y_src)

    # Clean NaNs
    f_threat = np.nan_to_num(f_threat, nan=0.0, posinf=1e6, neginf=0.0)
    f_source = np.nan_to_num(f_source, nan=0.0, posinf=1e6, neginf=0.0)

    results = []
    for idx, fname in enumerate(train_ds.feature_names):
        fdef = get_feature_by_name(fname)
        group = fdef.group if fdef else "unknown"

        f_th = float(round(float(f_threat[idx]), 2))
        f_so = float(round(float(f_source[idx]), 2))
        ratio = float(round(f_so / max(f_th, 1.0), 3))

        # Classification of feature nature
        if ratio > 5.0:
            nature = "dominant_source_fingerprint"
        elif ratio > 1.5:
            nature = "source_correlated"
        elif ratio < 0.5 and f_th > 50.0:
            nature = "strong_threat_signal"
        else:
            nature = "dual_correlated"

        results.append({
            "feature": fname,
            "group": group,
            "f_statistic_threat": f_th,
            "f_statistic_source": f_so,
            "source_to_threat_ratio": ratio,
            "classification": nature,
        })

    # Sort by source_to_threat_ratio descending
    results.sort(key=lambda x: x["source_to_threat_ratio"], reverse=True)
    return results
