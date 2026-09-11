"""
Feature Group Ablation Engine for VERTEX Forensic Tabular ML.
Conducts Leave-One-Group-Out (LOGO) ablation across all registered feature groups
to quantify the predictive importance and forensic contribution of each evidence family.
"""
from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict
import numpy as np
import lightgbm as lgb
from lightgbm import LGBMClassifier, early_stopping, log_evaluation
import warnings

from app.features.registry import FEATURE_REGISTRY, get_feature_names
from app.ml.preprocessing.tabular_loader import TabularDataset
from app.ml.evaluation.metrics import evaluate_predictions
from app.ml.version import TARGET_CLASSES


def get_feature_group_map() -> Dict[str, List[str]]:
    """Returns mapping from feature group name to list of feature names."""
    group_map: Dict[str, List[str]] = defaultdict(list)
    for feat in FEATURE_REGISTRY:
        group_map[feat.group].append(feat.name)
    return dict(group_map)


def run_feature_group_ablation(
    train_ds: TabularDataset,
    val_ds: TabularDataset,
    n_estimators: int = 250,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Runs Leave-One-Group-Out (LOGO) ablation across all feature groups.
    Measures drop in Macro F1 and Phishing PR-AUC on the validation set.
    """
    group_map = get_feature_group_map()
    all_feature_names = train_ds.feature_names

    # 1. Baseline: All features
    baseline_model = LGBMClassifier(
        objective="multiclass",
        num_class=len(TARGET_CLASSES),
        learning_rate=0.05,
        n_estimators=n_estimators,
        num_leaves=31,
        subsample=0.8,
        subsample_freq=1,
        colsample_bytree=0.8,
        random_state=random_state,
        n_jobs=-1,
        verbose=-1,
    )
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore")
        baseline_model.fit(
            train_ds.X,
            train_ds.y,
            eval_set=[(val_ds.X, val_ds.y)],
            callbacks=[early_stopping(stopping_rounds=20, verbose=False), log_evaluation(0)],
        )

    base_probs = baseline_model.predict_proba(val_ds.X)
    base_metrics = evaluate_predictions(val_ds.y, base_probs, classes=TARGET_CLASSES)
    base_macro_f1 = base_metrics["macro_f1"]
    base_phish_f1 = base_metrics["phishing_focus"]["f1"]
    base_phish_pr = base_metrics["phishing_focus"]["pr_auc"]

    results: Dict[str, Any] = {
        "baseline": {
            "num_features": len(all_feature_names),
            "macro_f1": base_macro_f1,
            "phishing_f1": base_phish_f1,
            "phishing_pr_auc": base_phish_pr,
            "brier_score": base_metrics["brier_score"],
        },
        "groups": {},
        "rankings": [],
    }

    # 2. Iterate through each group (Leave-One-Group-Out)
    feature_name_to_idx = {name: idx for idx, name in enumerate(all_feature_names)}

    for group_name, group_feats in sorted(group_map.items()):
        # Indices to keep
        feats_to_drop = set(group_feats)
        keep_indices = [
            idx for idx, name in enumerate(all_feature_names)
            if name not in feats_to_drop
        ]

        X_train_sub = train_ds.X[:, keep_indices]
        X_val_sub = val_ds.X[:, keep_indices]

        ablated_model = LGBMClassifier(
            objective="multiclass",
            num_class=len(TARGET_CLASSES),
            learning_rate=0.05,
            n_estimators=n_estimators,
            num_leaves=31,
            subsample=0.8,
            subsample_freq=1,
            colsample_bytree=0.8,
            random_state=random_state,
            n_jobs=-1,
            verbose=-1,
        )

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            ablated_model.fit(
                X_train_sub,
                train_ds.y,
                eval_set=[(X_val_sub, val_ds.y)],
                callbacks=[early_stopping(stopping_rounds=20, verbose=False), log_evaluation(0)],
            )

        abl_probs = ablated_model.predict_proba(X_val_sub)
        abl_metrics = evaluate_predictions(val_ds.y, abl_probs, classes=TARGET_CLASSES)

        f1_drop = float(round(base_macro_f1 - abl_metrics["macro_f1"], 4))
        phish_drop = float(round(base_phish_pr - abl_metrics["phishing_focus"]["pr_auc"], 4))

        results["groups"][group_name] = {
            "num_features_ablated": len(group_feats),
            "num_features_remaining": len(keep_indices),
            "macro_f1": abl_metrics["macro_f1"],
            "phishing_f1": abl_metrics["phishing_focus"]["f1"],
            "phishing_pr_auc": abl_metrics["phishing_focus"]["pr_auc"],
            "macro_f1_drop": f1_drop,
            "phishing_pr_auc_drop": phish_drop,
        }

    # 3. Rank groups by importance (largest drop in Macro F1 when ablated)
    ranked = sorted(
        results["groups"].items(),
        key=lambda item: item[1]["macro_f1_drop"],
        reverse=True,
    )
    results["rankings"] = [
        {
            "rank": rank + 1,
            "group": g_name,
            "num_features": data["num_features_ablated"],
            "f1_drop": data["macro_f1_drop"],
            "pr_auc_drop": data["phishing_pr_auc_drop"],
        }
        for rank, (g_name, data) in enumerate(ranked)
    ]

    return results


def format_ablation_table(ablation_dict: Dict[str, Any]) -> str:
    """Generates Markdown table summarizing feature group ablation results."""
    rankings = ablation_dict.get("rankings", [])
    base = ablation_dict.get("baseline", {})
    lines = [
        f"**Baseline (All {base.get('num_features', 125)} Features):** Macro F1 = {base.get('macro_f1', 0.0):.4f} | Phishing PR-AUC = {base.get('phishing_pr_auc', 0.0):.4f}\n",
        "| Rank | Feature Group | Features | Macro F1 Drop | Phishing PR-AUC Drop | Status |",
        "|:----:|:--------------|:--------:|:-------------:|:--------------------:|:-------|",
    ]
    for r in rankings:
        status = "Crucial" if r["f1_drop"] > 0.01 else ("Significant" if r["f1_drop"] > 0.002 else "Complementary")
        lines.append(
            f"| {r['rank']:^4} | {r['group']:<20} | {r['num_features']:^8} | "
            f"{r['f1_drop']:>13.4f} | {r['pr_auc_drop']:>20.4f} | {status:<13} |"
        )
    return "\n".join(lines)
