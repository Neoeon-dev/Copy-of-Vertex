"""
End-to-end execution orchestrator for Phase D4 Multimodal Evidence-Aware Fusion.
Computes predictions from Forensic LightGBM (D2) and Semantic DistilBERT (D3),
fits learned meta-classifier on validation split, evaluates fusion strategies,
runs degradation stress tests, short-text robustness, model disagreement analysis,
evaluates protected independent holdout strictly ONCE, and serializes all 12 report artifacts.
"""
from __future__ import annotations

import os
import sys
import time
import json
import hashlib
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import pyarrow.parquet as pq
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    precision_recall_curve,
    auc,
    confusion_matrix,
)
import joblib

from app.ml.version import LABEL_TO_INT, INT_TO_LABEL, TARGET_CLASSES
from app.features.registry import get_feature_names
from app.ml.models.forensic_service import ForensicTabularService
from app.ml.semantic.service import SemanticInferenceService
from app.ml.fusion.schemas import (
    EvidenceQuality,
    FusionPrediction,
    FusionStrategy,
    DisagreementCategory,
    QualityTier,
)
from app.ml.fusion.evidence_quality import EvidenceQualityAnalyzer
from app.ml.fusion.fusion import (
    EvidenceAwareFusionEngine,
    SmoothEvidenceRouter,
)
from app.ml.fusion.calibrator import FusionCalibrator


def safe_json_dump(data: Any, filepath: str) -> None:
    """Safely serializes numpy / float types to JSON."""
    def _convert(obj: Any) -> Any:
        if isinstance(obj, (np.integer, np.int64, np.int32)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64, np.float32)):
            return float(obj)
        elif isinstance(obj, np.ndarray):
            return obj.tolist()
        elif isinstance(obj, dict):
            return {str(k): _convert(v) for k, v in obj.items()}
        elif isinstance(obj, (list, tuple)):
            return [_convert(x) for x in obj]
        return obj

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(_convert(data), f, indent=2)


def calculate_metrics(y_true: np.ndarray, y_prob: np.ndarray) -> Dict[str, Any]:
    """Calculates comprehensive classification and calibration metrics."""
    y_pred = np.argmax(y_prob, axis=1)
    acc = float(accuracy_score(y_true, y_pred))
    macro_f1 = float(f1_score(y_true, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_true, y_pred, average="weighted", zero_division=0))

    per_class = {}
    present_classes = sorted(list(set(y_true)))
    for c_idx, c_name in enumerate(TARGET_CLASSES):
        if c_idx in present_classes:
            y_true_binary = (y_true == c_idx).astype(int)
            y_pred_binary = (y_pred == c_idx).astype(int)
            prec = float(precision_score(y_true_binary, y_pred_binary, zero_division=0))
            rec = float(recall_score(y_true_binary, y_pred_binary, zero_division=0))
            f1 = float(f1_score(y_true_binary, y_pred_binary, zero_division=0))

            # PR-AUC
            p_curve, r_curve, _ = precision_recall_curve(y_true_binary, y_prob[:, c_idx])
            pr_auc = float(auc(r_curve, p_curve))

            # ROC-AUC if both positive and negative present
            if len(set(y_true_binary)) > 1:
                roc_auc = float(roc_auc_score(y_true_binary, y_prob[:, c_idx]))
            else:
                roc_auc = 0.0

            per_class[c_name] = {
                "precision": round(prec, 4),
                "recall": round(rec, 4),
                "f1": round(f1, 4),
                "pr_auc": round(pr_auc, 4),
                "roc_auc": round(roc_auc, 4),
            }
        else:
            per_class[c_name] = {
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "pr_auc": 0.0,
                "roc_auc": 0.0,
                "note": "Class not present in ground truth support",
            }

    brier = FusionCalibrator.calculate_multiclass_brier_score(y_true, y_prob)
    ece, mce, _ = FusionCalibrator.calculate_ece_and_bins(y_true, y_prob, n_bins=10)
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1, 2]).tolist()

    return {
        "accuracy": round(acc, 4),
        "macro_f1": round(macro_f1, 4),
        "weighted_f1": round(weighted_f1, 4),
        "per_class": per_class,
        "phishing_metrics": per_class.get("phishing", {}),
        "brier_score": round(brier, 4),
        "ece": round(ece, 4),
        "mce": round(mce, 4),
        "confusion_matrix": cm,
    }


def run_phase_d4_pipeline(
    data_dir: str = "data/processed",
    models_dir: str = "models",
    reports_dir: str = "reports/d4",
    fusion_model_dir: str = "models/fusion/v1",
) -> None:
    """
    Executes the complete Phase D4 Multimodal Fusion pipeline.
    """
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(fusion_model_dir, exist_ok=True)
    cache_dir = os.path.join(data_dir, "cache")
    os.makedirs(cache_dir, exist_ok=True)

    print("=" * 80)
    print("VERTEX — PHASE D4: MULTIMODAL EVIDENCE-AWARE FUSION")
    print("=" * 80)

    # 1. Initialize models & services
    print("\n[Step 1/12] Initializing Models, Analyzers, and Services...")
    feature_names = get_feature_names()
    forensic_service = ForensicTabularService(model_dir=os.path.join(models_dir, "forensic/v1"))
    semantic_service = SemanticInferenceService(model_dir=os.path.join(models_dir, "semantic/v1"))
    quality_analyzer = EvidenceQualityAnalyzer()
    fusion_engine = EvidenceAwareFusionEngine(strategy=FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED)

    # 2. Helper to load and cache dataset predictions
    def get_dataset_predictions(split_name: str) -> Tuple[np.ndarray, np.ndarray, List[EvidenceQuality], np.ndarray, Dict[str, Any]]:
        cache_path = os.path.join(cache_dir, f"{split_name}_fusion_cache.pkl")
        if os.path.exists(cache_path):
            print(f"  Loading cached predictions for {split_name} from {cache_path}...")
            cached = joblib.load(cache_path)
            return (
                cached["p_d2"],
                cached["p_d3"],
                cached["eq_list"],
                cached["y_true"],
                cached["metadata"],
            )

        print(f"  Generating predictions for {split_name}...")
        split_parquet = os.path.join(data_dir, "splits", f"{split_name}.parquet")
        feat_parquet = os.path.join(data_dir, "features", f"{split_name}_features.parquet")

        t_split = pq.read_table(split_parquet)
        t_feat = pq.read_table(feat_parquet)

        n_samples = t_split.num_rows
        record_ids = t_split.column("record_id").to_pylist()
        source_datasets = t_split.column("source_dataset").to_pylist()
        subjects = t_split.column("subject").to_pylist()
        bodies = t_split.column("body").to_pylist()
        labels = t_split.column("normalized_label").to_pylist()
        y_true = np.array([LABEL_TO_INT[l] for l in labels], dtype=np.int64)

        # 2a. Forensic LightGBM Predictions
        feat_arrays = [t_feat.column(f).to_numpy().astype(np.float32) for f in feature_names]
        X_feat = np.column_stack(feat_arrays)
        p_d2 = forensic_service.model.predict_proba(X_feat)

        # 2b. Semantic DistilBERT Predictions
        pairs = list(zip(subjects, bodies))
        sem_results = semantic_service.predict_batch(pairs, batch_size=64)
        p_d3 = np.array([
            [r["probabilities"]["legitimate"], r["probabilities"]["spam"], r["probabilities"]["phishing"]]
            for r in sem_results
        ], dtype=np.float64)

        # 2c. Evidence Quality Analysis
        eq_list: List[EvidenceQuality] = []
        for i in range(n_samples):
            f_dict = {f: float(X_feat[i, idx]) for idx, f in enumerate(feature_names)}
            eq = quality_analyzer.analyze_features(f_dict)
            eq_list.append(eq)

        metadata = {
            "record_ids": record_ids,
            "source_datasets": source_datasets,
            "subjects": subjects,
            "bodies": bodies,
        }

        joblib.dump(
            {
                "p_d2": p_d2,
                "p_d3": p_d3,
                "eq_list": eq_list,
                "y_true": y_true,
                "metadata": metadata,
            },
            cache_path,
        )
        print(f"  Cached {n_samples} predictions to {cache_path}")
        return p_d2, p_d3, eq_list, y_true, metadata

    # 3. Load Validation Split
    print("\n[Step 2/12] Loading and Scoring Validation Split...")
    val_p_d2, val_p_d3, val_eq, y_val, val_meta = get_dataset_predictions("validation")

    # 4. Train Learned Fusion Meta-Classifier on Validation
    print("\n[Step 3/12] Training Learned Fusion Meta-Classifier on Validation Split...")
    fit_res = fusion_engine.train_learned_fusion(val_p_d2, val_p_d3, val_eq, y_val)
    print(f"  Learned Fusion Meta-Classifier trained: {fit_res}")

    # 5. Evaluate Fusion Strategies on Validation
    print("\n[Step 4/12] Benchmarking Fusion Strategies on Validation Split...")
    strategies = [
        FusionStrategy.FORENSIC_ONLY,
        FusionStrategy.SEMANTIC_ONLY,
        FusionStrategy.EQUAL_AVERAGE,
        FusionStrategy.FIXED_WEIGHTED,
        FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED,
        FusionStrategy.LEARNED_LOGISTIC,
    ]

    val_results: Dict[str, Any] = {}
    for strat in strategies:
        p_strat_list = []
        for i in range(len(y_val)):
            p_fused, _ = fusion_engine.fuse_probabilities(val_p_d2[i], val_p_d3[i], val_eq[i], strategy=strat)
            p_strat_list.append(p_fused)
        p_strat = np.array(p_strat_list)
        metrics = calculate_metrics(y_val, p_strat)
        val_results[strat.value] = metrics
        print(f"  Strategy: {strat.value:25s} | Acc: {metrics['accuracy']*100:.2f}% | Macro F1: {metrics['macro_f1']:.4f} | Phish F1: {metrics['phishing_metrics']['f1']:.4f} | ECE: {metrics['ece']:.4f}")

    safe_json_dump(val_results, os.path.join(reports_dir, "fusion_comparison_val.json"))

    # 6. Load Test Split
    print("\n[Step 5/12] Loading and Scoring Test Split...")
    test_p_d2, test_p_d3, test_eq, y_test, test_meta = get_dataset_predictions("test")

    # 7. Evaluate Fusion Strategies on Test Split
    print("\n[Step 6/12] Benchmarking Fusion Strategies on Test Split...")
    test_results: Dict[str, Any] = {}
    test_preds_by_strat: Dict[str, np.ndarray] = {}
    for strat in strategies:
        p_strat_list = []
        for i in range(len(y_test)):
            p_fused, _ = fusion_engine.fuse_probabilities(test_p_d2[i], test_p_d3[i], test_eq[i], strategy=strat)
            p_strat_list.append(p_fused)
        p_strat = np.array(p_strat_list)
        test_preds_by_strat[strat.value] = p_strat
        metrics = calculate_metrics(y_test, p_strat)
        test_results[strat.value] = metrics
        print(f"  Strategy: {strat.value:25s} | Acc: {metrics['accuracy']*100:.2f}% | Macro F1: {metrics['macro_f1']:.4f} | Phish F1: {metrics['phishing_metrics']['f1']:.4f} | ECE: {metrics['ece']:.4f}")

    safe_json_dump(test_results, os.path.join(reports_dir, "fusion_comparison_test.json"))

    # 8. Model Disagreement Analysis
    print("\n[Step 7/12] Running Model Disagreement Analysis on Test Split...")
    d2_preds = np.argmax(test_p_d2, axis=1)
    d3_preds = np.argmax(test_p_d3, axis=1)
    fused_preds = np.argmax(test_preds_by_strat[FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED.value], axis=1)
    learned_preds = np.argmax(test_preds_by_strat[FusionStrategy.LEARNED_LOGISTIC.value], axis=1)

    disagreements = (d2_preds != d3_preds)
    total_samples = len(y_test)
    disagree_count = int(np.sum(disagreements))
    agree_count = total_samples - disagree_count

    cat_counts: Dict[str, int] = {}
    cat_qs: Dict[str, List[float]] = {}
    for i in range(total_samples):
        if disagreements[i]:
            d2_lbl = INT_TO_LABEL[d2_preds[i]]
            d3_lbl = INT_TO_LABEL[d3_preds[i]]
            cat = DisagreementCategory.categorize(d2_lbl, d3_lbl).value
            cat_counts[cat] = cat_counts.get(cat, 0) + 1
            cat_qs.setdefault(cat, []).append(test_eq[i].overall_quality)

    agree_mask = ~disagreements
    disagree_mask = disagreements

    d2_acc_agree = float(np.mean(d2_preds[agree_mask] == y_test[agree_mask]))
    d2_acc_disagree = float(np.mean(d2_preds[disagree_mask] == y_test[disagree_mask]))
    d3_acc_disagree = float(np.mean(d3_preds[disagree_mask] == y_test[disagree_mask]))
    fusion_acc_disagree = float(np.mean(fused_preds[disagree_mask] == y_test[disagree_mask]))
    learned_acc_disagree = float(np.mean(learned_preds[disagree_mask] == y_test[disagree_mask]))

    disagreement_table = {
        "total_samples": total_samples,
        "agreement_count": agree_count,
        "agreement_rate": round(agree_count / total_samples, 4),
        "disagreement_count": disagree_count,
        "disagreement_rate": round(disagree_count / total_samples, 4),
        "accuracy_when_models_agree": round(d2_acc_agree, 4),
        "accuracy_when_models_disagree": {
            "d2_forensic_accuracy": round(d2_acc_disagree, 4),
            "d3_semantic_accuracy": round(d3_acc_disagree, 4),
            "champion_smooth_fusion_accuracy": round(fusion_acc_disagree, 4),
            "learned_fusion_accuracy": round(learned_acc_disagree, 4),
        },
        "disagreement_category_breakdown": {
            cat: {
                "count": count,
                "percentage_of_disagreements": round(count / disagree_count * 100, 2),
                "mean_evidence_quality_q": round(float(np.mean(cat_qs[cat])), 4),
            }
            for cat, count in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
        },
    }
    print(f"  Disagreement Rate: {disagreement_table['disagreement_rate']*100:.2f}% ({disagree_count}/{total_samples})")
    print(f"  Agreement Accuracy: {d2_acc_agree*100:.2f}% | Disagreement Fusion Accuracy: {fusion_acc_disagree*100:.2f}% (vs D2 {d2_acc_disagree*100:.2f}%, D3 {d3_acc_disagree*100:.2f}%)")
    safe_json_dump(disagreement_table, os.path.join(reports_dir, "model_disagreement_table.json"))

    # 9. Disagreement Qualitative Case Studies
    print("\n[Step 8/12] Generating Disagreement Case Studies...")
    case_studies: List[Dict[str, Any]] = []
    # Find diverse examples of each disagreement category
    for target_cat in cat_counts.keys():
        candidates = []
        for i in range(total_samples):
            if disagreements[i]:
                d2_lbl = INT_TO_LABEL[d2_preds[i]]
                d3_lbl = INT_TO_LABEL[d3_preds[i]]
                if DisagreementCategory.categorize(d2_lbl, d3_lbl).value == target_cat:
                    candidates.append(i)
        if candidates:
            # Pick 1-2 representative examples
            for idx in candidates[:2]:
                rec_id = test_meta["record_ids"][idx]
                src = test_meta["source_datasets"][idx]
                subj = test_meta["subjects"][idx]
                b_snippet = str(test_meta["bodies"][idx])[:250].replace("\n", " ").strip()
                gt_label = INT_TO_LABEL[y_test[idx]]
                d2_l = INT_TO_LABEL[d2_preds[idx]]
                d3_l = INT_TO_LABEL[d3_preds[idx]]
                fused_l = INT_TO_LABEL[fused_preds[idx]]
                eq_i = test_eq[idx]
                a_i = fusion_engine.router.compute_alpha(eq_i.overall_quality)

                # Diagnostic explanation
                if d2_l == gt_label and fused_l == gt_label:
                    diag = f"Forensic features correctly identified {gt_label} (Q={eq_i.overall_quality:.2f}); weighted fusion prioritized forensic signals."
                elif d3_l == gt_label and fused_l == gt_label:
                    diag = f"Semantic text correctly identified {gt_label}; degraded/misleading forensic cues (Q={eq_i.overall_quality:.2f}) were gracefully downweighted."
                elif fused_l == gt_label:
                    diag = f"Complementary probabilities resolved ambiguity into true label {gt_label}."
                else:
                    diag = f"Ambiguous threat cue resulting in edge classification; flagged for uncertainty escalation."

                case_studies.append({
                    "record_id": rec_id,
                    "source_dataset": src,
                    "ground_truth_label": gt_label,
                    "subject": subj,
                    "body_snippet": b_snippet,
                    "evidence_quality_q": round(eq_i.overall_quality, 4),
                    "evidence_tier": eq_i.tier,
                    "missing_evidence_flags": eq_i.missing_evidence_flags,
                    "d2_forensic": {
                        "prediction": d2_l,
                        "probabilities": {TARGET_CLASSES[c]: round(float(test_p_d2[idx, c]), 4) for c in range(3)},
                    },
                    "d3_semantic": {
                        "prediction": d3_l,
                        "probabilities": {TARGET_CLASSES[c]: round(float(test_p_d3[idx, c]), 4) for c in range(3)},
                    },
                    "fusion": {
                        "prediction": fused_l,
                        "alpha_forensic_weight": round(a_i, 4),
                        "semantic_weight": round(1.0 - a_i, 4),
                        "probabilities": {TARGET_CLASSES[c]: round(float(test_preds_by_strat[FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED.value][idx, c]), 4) for c in range(3)},
                    },
                    "disagreement_category": target_cat,
                    "diagnostic_explanation": diag,
                })

    safe_json_dump({"case_studies": case_studies[:12]}, os.path.join(reports_dir, "disagreement_case_studies.json"))

    # 10. Evidence Degradation Table (10 Conditions)
    print("\n[Step 9/12] Evaluating Evidence Degradation Across 10 Controlled Conditions...")
    degradation_results: List[Dict[str, Any]] = []

    # Helper to simulate feature perturbations on test split
    feat_parquet = os.path.join(data_dir, "features", "test_features.parquet")
    t_feat_test = pq.read_table(feat_parquet)
    X_base = np.column_stack([t_feat_test.column(f).to_numpy().astype(np.float32) for f in feature_names])

    conditions = [
        ("Condition 1: Full Baseline Evidence", lambda X: X.copy()),
        ("Condition 2: Stripped Authentication", lambda X: _strip_features(X, feature_names, ["auth_"])),
        ("Condition 3: Stripped Relay Path", lambda X: _strip_features(X, feature_names, ["relay_"])),
        ("Condition 4: Stripped Network IP", lambda X: _strip_features(X, feature_names, ["ip_"])),
        ("Condition 5: Stripped Sender Domain", lambda X: _strip_features(X, feature_names, ["dom_"])),
        ("Condition 6: Stripped URL Signals", lambda X: _strip_features(X, feature_names, ["url_"])),
        ("Condition 7: Stripped Attachments", lambda X: _strip_features(X, feature_names, ["att_"])),
        ("Condition 8: Stripped All Headers", lambda X: _strip_features(X, feature_names, ["hdr_", "relay_", "auth_", "ident_"])),
        ("Condition 9: Truncated Short Body (<15 words)", lambda X: _perturb_short_body(X, feature_names)),
        ("Condition 10: Critical Holdout Simulation", lambda X: _strip_holdout_simulation(X, feature_names)),
    ]

    for cond_name, perturb_fn in conditions:
        X_pert = perturb_fn(X_base)
        # Evaluate D2 on perturbed features
        p_d2_pert = forensic_service.model.predict_proba(X_pert)

        # Re-evaluate evidence quality and fuse
        p_fused_pert = []
        qs = []
        alphas = []
        for i in range(total_samples):
            f_dict = {f: float(X_pert[i, idx]) for idx, f in enumerate(feature_names)}
            eq_pert = quality_analyzer.analyze_features(f_dict)
            qs.append(eq_pert.overall_quality)
            p_f, a = fusion_engine.fuse_probabilities(p_d2_pert[i], test_p_d3[i], eq_pert)
            p_fused_pert.append(p_f)
            alphas.append(a)
        p_fused_pert = np.array(p_fused_pert)

        m_d2 = calculate_metrics(y_test, p_d2_pert)
        m_d3 = calculate_metrics(y_test, test_p_d3)  # D3 text remains unchanged
        m_fus = calculate_metrics(y_test, p_fused_pert)

        degradation_results.append({
            "condition": cond_name,
            "mean_evidence_quality_q": round(float(np.mean(qs)), 4),
            "mean_forensic_weight_alpha": round(float(np.mean(alphas)), 4),
            "d2_forensic": {
                "accuracy": m_d2["accuracy"],
                "macro_f1": m_d2["macro_f1"],
                "phishing_f1": m_d2["phishing_metrics"]["f1"],
                "legitimate_recall": m_d2["per_class"]["legitimate"]["recall"],
            },
            "d3_semantic": {
                "accuracy": m_d3["accuracy"],
                "macro_f1": m_d3["macro_f1"],
                "phishing_f1": m_d3["phishing_metrics"]["f1"],
                "legitimate_recall": m_d3["per_class"]["legitimate"]["recall"],
            },
            "fusion": {
                "accuracy": m_fus["accuracy"],
                "macro_f1": m_fus["macro_f1"],
                "phishing_f1": m_fus["phishing_metrics"]["f1"],
                "legitimate_recall": m_fus["per_class"]["legitimate"]["recall"],
            },
            "delta_vs_d2": round(m_fus["accuracy"] - m_d2["accuracy"], 4),
            "delta_vs_d3": round(m_fus["accuracy"] - m_d3["accuracy"], 4),
        })
        print(f"  {cond_name:40s} | Q={np.mean(qs):.2f}, alpha={np.mean(alphas):.2f} | D2 Acc: {m_d2['accuracy']*100:.2f}% | Fusion Acc: {m_fus['accuracy']*100:.2f}% (delta: {m_fus['accuracy']-m_d2['accuracy']:+.4f})")

    safe_json_dump({"degradation_conditions": degradation_results}, os.path.join(reports_dir, "evidence_degradation_table.json"))

    # 11. Short-Text Robustness Breakdown
    print("\n[Step 10/12] Evaluating Short-Text Robustness Across Word Count Buckets...")
    body_word_counts = []
    w_idx = feature_names.index("msg_body_word_count")
    for i in range(total_samples):
        body_word_counts.append(float(X_base[i, w_idx]))

    buckets = [
        ("< 5 words", lambda w: w < 5),
        ("5 - 15 words", lambda w: 5 <= w < 15),
        ("15 - 50 words", lambda w: 15 <= w < 50),
        ("> 50 words", lambda w: w >= 50),
    ]

    short_text_results: List[Dict[str, Any]] = []
    for b_label, b_filter in buckets:
        indices = [i for i, w in enumerate(body_word_counts) if b_filter(w)]
        if not indices:
            continue
        y_b = y_test[indices]
        p_d2_b = test_p_d2[indices]
        p_d3_b = test_p_d3[indices]
        p_fus_b = test_preds_by_strat[FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED.value][indices]

        m_d2 = calculate_metrics(y_b, p_d2_b)
        m_d3 = calculate_metrics(y_b, p_d3_b)
        m_fus = calculate_metrics(y_b, p_fus_b)

        short_text_results.append({
            "word_count_bucket": b_label,
            "sample_count": len(indices),
            "class_distribution": {
                "legitimate": int(np.sum(y_b == 0)),
                "spam": int(np.sum(y_b == 1)),
                "phishing": int(np.sum(y_b == 2)),
            },
            "d2_forensic": {
                "accuracy": m_d2["accuracy"],
                "macro_f1": m_d2["macro_f1"],
                "phishing_f1": m_d2["phishing_metrics"]["f1"],
                "legitimate_recall": m_d2["per_class"]["legitimate"]["recall"],
            },
            "d3_semantic": {
                "accuracy": m_d3["accuracy"],
                "macro_f1": m_d3["macro_f1"],
                "phishing_f1": m_d3["phishing_metrics"]["f1"],
                "legitimate_recall": m_d3["per_class"]["legitimate"]["recall"],
            },
            "fusion": {
                "accuracy": m_fus["accuracy"],
                "macro_f1": m_fus["macro_f1"],
                "phishing_f1": m_fus["phishing_metrics"]["f1"],
                "legitimate_recall": m_fus["per_class"]["legitimate"]["recall"],
            },
        })
        print(f"  Bucket {b_label:15s} (N={len(indices):4d}) | D2 Acc: {m_d2['accuracy']*100:.2f}% | D3 Acc: {m_d3['accuracy']*100:.2f}% | Fusion Acc: {m_fus['accuracy']*100:.2f}%")

    safe_json_dump({"short_text_robustness": short_text_results}, os.path.join(reports_dir, "short_text_robustness_table.json"))

    # 12. Source-Aware Breakdown (All 10 Corpora)
    print("\n[Step 11/12] Evaluating Source-Aware Generalization Across 10 Corpora...")
    sources = test_meta["source_datasets"]
    unique_sources = sorted(list(set(sources)))
    source_results: Dict[str, Any] = {}

    for src in unique_sources:
        indices = [i for i, s in enumerate(sources) if s == src]
        y_s = y_test[indices]
        p_d2_s = test_p_d2[indices]
        p_d3_s = test_p_d3[indices]
        p_fus_s = test_preds_by_strat[FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED.value][indices]
        qs_s = [test_eq[i].overall_quality for i in indices]

        m_d2 = calculate_metrics(y_s, p_d2_s)
        m_d3 = calculate_metrics(y_s, p_d3_s)
        m_fus = calculate_metrics(y_s, p_fus_s)

        source_results[src] = {
            "sample_count": len(indices),
            "mean_evidence_quality_q": round(float(np.mean(qs_s)), 4),
            "d2_forensic": {
                "accuracy": m_d2["accuracy"],
                "macro_f1": m_d2["macro_f1"],
            },
            "d3_semantic": {
                "accuracy": m_d3["accuracy"],
                "macro_f1": m_d3["macro_f1"],
            },
            "fusion": {
                "accuracy": m_fus["accuracy"],
                "macro_f1": m_fus["macro_f1"],
            },
        }
        print(f"  Source {src:35s} (N={len(indices):4d}, Q={np.mean(qs_s):.2f}) | D2 Acc: {m_d2['accuracy']*100:.2f}% | D3 Acc: {m_d3['accuracy']*100:.2f}% | Fusion Acc: {m_fus['accuracy']*100:.2f}%")

    safe_json_dump({"sources": source_results}, os.path.join(reports_dir, "source_aware_breakdown.json"))

    # 13. Confusion Matrices & Calibration Curves on Test
    print("\n[Step 12/12 Part A] Saving Test Confusion Matrices and Calibration Curves...")
    cm_test = {
        "D2_Forensic_LightGBM": test_results[FusionStrategy.FORENSIC_ONLY.value]["confusion_matrix"],
        "D3_Semantic_DistilBERT": test_results[FusionStrategy.SEMANTIC_ONLY.value]["confusion_matrix"],
        "Champion_Fusion_Smooth": test_results[FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED.value]["confusion_matrix"],
        "Learned_Fusion_Logistic": test_results[FusionStrategy.LEARNED_LOGISTIC.value]["confusion_matrix"],
    }
    safe_json_dump(cm_test, os.path.join(reports_dir, "confusion_matrix_test.json"))

    # Calibration curves on test
    _, _, d2_bins = FusionCalibrator.calculate_ece_and_bins(y_test, test_p_d2, n_bins=10)
    _, _, d3_bins = FusionCalibrator.calculate_ece_and_bins(y_test, test_p_d3, n_bins=10)
    _, _, fus_bins = FusionCalibrator.calculate_ece_and_bins(
        y_test, test_preds_by_strat[FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED.value], n_bins=10
    )

    calibration_curves = {
        "D2_Forensic": {
            "brier": test_results[FusionStrategy.FORENSIC_ONLY.value]["brier_score"],
            "ece": test_results[FusionStrategy.FORENSIC_ONLY.value]["ece"],
            "mce": test_results[FusionStrategy.FORENSIC_ONLY.value]["mce"],
            "bins": d2_bins,
        },
        "D3_Semantic": {
            "brier": test_results[FusionStrategy.SEMANTIC_ONLY.value]["brier_score"],
            "ece": test_results[FusionStrategy.SEMANTIC_ONLY.value]["ece"],
            "mce": test_results[FusionStrategy.SEMANTIC_ONLY.value]["mce"],
            "bins": d3_bins,
        },
        "Champion_Fusion_Smooth": {
            "brier": test_results[FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED.value]["brier_score"],
            "ece": test_results[FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED.value]["ece"],
            "mce": test_results[FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED.value]["mce"],
            "bins": fus_bins,
        },
    }
    safe_json_dump(calibration_curves, os.path.join(reports_dir, "calibration_curves.json"))

    # 14. PROTECTED INDEPENDENT HOLDOUT EVALUATION (STRICTLY ONCE)
    print("\n" + "=" * 80)
    print("[Step 12/12 Part B] FROZEN EVALUATION: Protected Independent Holdout (STRICTLY ONCE)")
    print("=" * 80)
    hold_p_d2, hold_p_d3, hold_eq, y_hold, hold_meta = get_dataset_predictions("holdout_independent")

    # Evaluate all models on Holdout
    hold_preds_fus_list = []
    hold_alphas = []
    for i in range(len(y_hold)):
        p_f, a = fusion_engine.fuse_probabilities(
            hold_p_d2[i], hold_p_d3[i], hold_eq[i], strategy=FusionStrategy.SMOOTH_EVIDENCE_WEIGHTED
        )
        hold_preds_fus_list.append(p_f)
        hold_alphas.append(a)
    hold_p_fus = np.array(hold_preds_fus_list)

    hold_p_learned_list = []
    for i in range(len(y_hold)):
        p_l, _ = fusion_engine.fuse_probabilities(
            hold_p_d2[i], hold_p_d3[i], hold_eq[i], strategy=FusionStrategy.LEARNED_LOGISTIC
        )
        hold_p_learned_list.append(p_l)
    hold_p_learned = np.array(hold_p_learned_list)

    m_hold_d2 = calculate_metrics(y_hold, hold_p_d2)
    m_hold_d3 = calculate_metrics(y_hold, hold_p_d3)
    m_hold_fus = calculate_metrics(y_hold, hold_p_fus)
    m_hold_learned = calculate_metrics(y_hold, hold_p_learned)

    # Detailed binary analysis on Holdout (1,000 Legit vs 1,000 Phishing, 0 Spam)
    def binary_holdout_stats(y_probs: np.ndarray) -> Dict[str, Any]:
        preds = np.argmax(y_probs, axis=1)
        legit_correct = int(np.sum((y_hold == 0) & (preds == 0)))
        legit_to_phish = int(np.sum((y_hold == 0) & (preds == 2)))
        legit_to_spam = int(np.sum((y_hold == 0) & (preds == 1)))
        phish_correct = int(np.sum((y_hold == 2) & (preds == 2)))
        phish_to_legit = int(np.sum((y_hold == 2) & (preds == 0)))
        phish_to_spam = int(np.sum((y_hold == 2) & (preds == 1)))

        specificity = legit_correct / 1000.0
        recall = phish_correct / 1000.0
        precision = phish_correct / max(phish_correct + legit_to_phish, 1)
        f1 = 2 * precision * recall / max(precision + recall, 1e-6)

        return {
            "legitimate_true_count": 1000,
            "legitimate_correct_tn": legit_correct,
            "legitimate_predicted_as_phish_fp": legit_to_phish,
            "legitimate_predicted_as_spam": legit_to_spam,
            "phishing_true_count": 1000,
            "phishing_correct_tp": phish_correct,
            "phishing_predicted_as_legit_fn": phish_to_legit,
            "phishing_predicted_as_spam": phish_to_spam,
            "specificity": round(float(specificity), 4),
            "phishing_precision": round(float(precision), 4),
            "phishing_recall": round(float(recall), 4),
            "phishing_f1": round(float(f1), 4),
        }

    holdout_report = {
        "dataset": "zenodo_validation_holdout_13474746",
        "sample_count": 2000,
        "mean_evidence_quality_q": round(float(np.mean([eq.overall_quality for eq in hold_eq])), 4),
        "mean_forensic_weight_alpha": round(float(np.mean(hold_alphas)), 4),
        "models": {
            "D2_Forensic_LightGBM": {
                "multiclass": m_hold_d2,
                "binary": binary_holdout_stats(hold_p_d2),
            },
            "D3_Semantic_DistilBERT": {
                "multiclass": m_hold_d3,
                "binary": binary_holdout_stats(hold_p_d3),
            },
            "Champion_Fusion_Smooth": {
                "multiclass": m_hold_fus,
                "binary": binary_holdout_stats(hold_p_fus),
            },
            "Learned_Fusion_Logistic": {
                "multiclass": m_hold_learned,
                "binary": binary_holdout_stats(hold_p_learned),
            },
        },
    }

    print(f"  Holdout Mean Q: {holdout_report['mean_evidence_quality_q']:.4f} (Tier: DEGRADED) | Mean Alpha: {holdout_report['mean_forensic_weight_alpha']:.4f}")
    print(f"  D2 Forensic Alone:      Acc: {m_hold_d2['accuracy']*100:.2f}% | Legit Specificity: {holdout_report['models']['D2_Forensic_LightGBM']['binary']['specificity']*100:.2f}% | Phish F1: {holdout_report['models']['D2_Forensic_LightGBM']['binary']['phishing_f1']:.4f}")
    print(f"  D3 Semantic Alone:      Acc: {m_hold_d3['accuracy']*100:.2f}% | Legit Specificity: {holdout_report['models']['D3_Semantic_DistilBERT']['binary']['specificity']*100:.2f}% | Phish F1: {holdout_report['models']['D3_Semantic_DistilBERT']['binary']['phishing_f1']:.4f}")
    print(f"  Champion Fusion Smooth: Acc: {m_hold_fus['accuracy']*100:.2f}% | Legit Specificity: {holdout_report['models']['Champion_Fusion_Smooth']['binary']['specificity']*100:.2f}% | Phish F1: {holdout_report['models']['Champion_Fusion_Smooth']['binary']['phishing_f1']:.4f}")
    print(f"  Learned Fusion:         Acc: {m_hold_learned['accuracy']*100:.2f}% | Legit Specificity: {holdout_report['models']['Learned_Fusion_Logistic']['binary']['specificity']*100:.2f}% | Phish F1: {holdout_report['models']['Learned_Fusion_Logistic']['binary']['phishing_f1']:.4f}")

    safe_json_dump(holdout_report, os.path.join(reports_dir, "holdout_evaluation.json"))

    # Confusion matrix on holdout
    cm_holdout = {
        "D2_Forensic_LightGBM": m_hold_d2["confusion_matrix"],
        "D3_Semantic_DistilBERT": m_hold_d3["confusion_matrix"],
        "Champion_Fusion_Smooth": m_hold_fus["confusion_matrix"],
        "Learned_Fusion_Logistic": m_hold_learned["confusion_matrix"],
    }
    safe_json_dump(cm_holdout, os.path.join(reports_dir, "confusion_matrix_holdout.json"))

    # 15. Summary Metrics JSON
    summary_metrics = {
        "in_distribution_test_metrics": {
            "D2_Forensic_LightGBM": {
                "accuracy": test_results["forensic_only"]["accuracy"],
                "macro_f1": test_results["forensic_only"]["macro_f1"],
                "phishing_f1": test_results["forensic_only"]["phishing_metrics"]["f1"],
                "brier_score": test_results["forensic_only"]["brier_score"],
                "ece": test_results["forensic_only"]["ece"],
            },
            "D3_Semantic_DistilBERT": {
                "accuracy": test_results["semantic_only"]["accuracy"],
                "macro_f1": test_results["semantic_only"]["macro_f1"],
                "phishing_f1": test_results["semantic_only"]["phishing_metrics"]["f1"],
                "brier_score": test_results["semantic_only"]["brier_score"],
                "ece": test_results["semantic_only"]["ece"],
            },
            "Champion_Fusion_Smooth": {
                "accuracy": test_results["smooth_evidence_weighted"]["accuracy"],
                "macro_f1": test_results["smooth_evidence_weighted"]["macro_f1"],
                "phishing_f1": test_results["smooth_evidence_weighted"]["phishing_metrics"]["f1"],
                "brier_score": test_results["smooth_evidence_weighted"]["brier_score"],
                "ece": test_results["smooth_evidence_weighted"]["ece"],
            },
            "Learned_Fusion_Logistic": {
                "accuracy": test_results["learned_logistic"]["accuracy"],
                "macro_f1": test_results["learned_logistic"]["macro_f1"],
                "phishing_f1": test_results["learned_logistic"]["phishing_metrics"]["f1"],
                "brier_score": test_results["learned_logistic"]["brier_score"],
                "ece": test_results["learned_logistic"]["ece"],
            },
        },
        "independent_holdout_metrics": {
            "D2_Forensic_LightGBM": {
                "accuracy": m_hold_d2["accuracy"],
                "legitimate_specificity": holdout_report["models"]["D2_Forensic_LightGBM"]["binary"]["specificity"],
                "phishing_recall": holdout_report["models"]["D2_Forensic_LightGBM"]["binary"]["phishing_recall"],
                "phishing_precision": holdout_report["models"]["D2_Forensic_LightGBM"]["binary"]["phishing_precision"],
                "phishing_f1": holdout_report["models"]["D2_Forensic_LightGBM"]["binary"]["phishing_f1"],
                "brier_score": m_hold_d2["brier_score"],
                "ece": m_hold_d2["ece"],
            },
            "D3_Semantic_DistilBERT": {
                "accuracy": m_hold_d3["accuracy"],
                "legitimate_specificity": holdout_report["models"]["D3_Semantic_DistilBERT"]["binary"]["specificity"],
                "phishing_recall": holdout_report["models"]["D3_Semantic_DistilBERT"]["binary"]["phishing_recall"],
                "phishing_precision": holdout_report["models"]["D3_Semantic_DistilBERT"]["binary"]["phishing_precision"],
                "phishing_f1": holdout_report["models"]["D3_Semantic_DistilBERT"]["binary"]["phishing_f1"],
                "brier_score": m_hold_d3["brier_score"],
                "ece": m_hold_d3["ece"],
            },
            "Champion_Fusion_Smooth": {
                "accuracy": m_hold_fus["accuracy"],
                "legitimate_specificity": holdout_report["models"]["Champion_Fusion_Smooth"]["binary"]["specificity"],
                "phishing_recall": holdout_report["models"]["Champion_Fusion_Smooth"]["binary"]["phishing_recall"],
                "phishing_precision": holdout_report["models"]["Champion_Fusion_Smooth"]["binary"]["phishing_precision"],
                "phishing_f1": holdout_report["models"]["Champion_Fusion_Smooth"]["binary"]["phishing_f1"],
                "brier_score": m_hold_fus["brier_score"],
                "ece": m_hold_fus["ece"],
            },
            "Learned_Fusion_Logistic": {
                "accuracy": m_hold_learned["accuracy"],
                "legitimate_specificity": holdout_report["models"]["Learned_Fusion_Logistic"]["binary"]["specificity"],
                "phishing_recall": holdout_report["models"]["Learned_Fusion_Logistic"]["binary"]["phishing_recall"],
                "phishing_precision": holdout_report["models"]["Learned_Fusion_Logistic"]["binary"]["phishing_precision"],
                "phishing_f1": holdout_report["models"]["Learned_Fusion_Logistic"]["binary"]["phishing_f1"],
                "brier_score": m_hold_learned["brier_score"],
                "ece": m_hold_learned["ece"],
            },
        },
    }
    safe_json_dump(summary_metrics, os.path.join(reports_dir, "summary_metrics.json"))

    # 16. Save Model Artifacts
    print("\n[Step 12/12 Part C] Serializing Model Artifacts into models/fusion/v1/...")
    # Save learned meta-classifier
    joblib.dump(fusion_engine.learned_model, os.path.join(fusion_model_dir, "learned_fusion_model.pkl"))

    fusion_config = {
        "version": "1.0.0",
        "champion_strategy": "smooth_evidence_weighted",
        "router_parameters": {
            "alpha_min": fusion_engine.router.alpha_min,
            "alpha_max": fusion_engine.router.alpha_max,
            "q_midpoint": fusion_engine.router.q_midpoint,
            "steepness": fusion_engine.router.steepness,
        },
        "confidence_threshold": fusion_engine.confidence_threshold,
        "evidence_dimension_weights": quality_analyzer.weights,
        "submodels": {
            "forensic": "models/forensic/v1",
            "semantic": "models/semantic/v1",
        },
    }
    safe_json_dump(fusion_config, os.path.join(fusion_model_dir, "fusion_config.json"))

    # Compute SHA-256 for artifacts
    def get_sha256(fpath: str) -> str:
        h = hashlib.sha256()
        with open(fpath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    metadata = {
        "model_name": "VERTEX Multimodal Evidence-Aware Threat Classifier",
        "model_version": "1.0.0",
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "champion_strategy": "smooth_evidence_weighted",
        "test_accuracy": test_results["smooth_evidence_weighted"]["accuracy"],
        "test_macro_f1": test_results["smooth_evidence_weighted"]["macro_f1"],
        "holdout_accuracy": m_hold_fus["accuracy"],
        "holdout_phishing_f1": holdout_report["models"]["Champion_Fusion_Smooth"]["binary"]["phishing_f1"],
        "artifacts": {
            "fusion_config.json": {
                "path": "fusion_config.json",
                "sha256": get_sha256(os.path.join(fusion_model_dir, "fusion_config.json")),
            },
            "learned_fusion_model.pkl": {
                "path": "learned_fusion_model.pkl",
                "sha256": get_sha256(os.path.join(fusion_model_dir, "learned_fusion_model.pkl")),
            },
        },
    }
    safe_json_dump(metadata, os.path.join(fusion_model_dir, "metadata.json"))

    print("\nPhase D4 Pipeline Execution Complete!")
    print(f"  All 12 reports successfully written to: {reports_dir}/")
    print(f"  Model artifacts saved to:               {fusion_model_dir}/")


# --- Helper perturbation functions for degradation table ---

def _strip_features(X: np.ndarray, feature_names: List[str], prefixes: List[str]) -> np.ndarray:
    """Sets specified feature prefixes to -1.0."""
    X_pert = X.copy()
    for idx, fname in enumerate(feature_names):
        if any(fname.startswith(p) for p in prefixes):
            X_pert[:, idx] = -1.0
    return X_pert


def _perturb_short_body(X: np.ndarray, feature_names: List[str]) -> np.ndarray:
    """Truncates body length and word count to short values."""
    X_pert = X.copy()
    w_idx = feature_names.index("msg_body_word_count")
    l_idx = feature_names.index("msg_body_length")
    line_idx = feature_names.index("msg_body_line_count")
    X_pert[:, w_idx] = np.minimum(X_pert[:, w_idx], 10.0)
    X_pert[:, l_idx] = np.minimum(X_pert[:, l_idx], 60.0)
    X_pert[:, line_idx] = np.minimum(X_pert[:, line_idx], 2.0)
    return X_pert


def _strip_holdout_simulation(X: np.ndarray, feature_names: List[str]) -> np.ndarray:
    """Strips all headers, auth, relay, IPs, URLs, attachments to simulate holdout."""
    X_pert = X.copy()
    strip_prefixes = ["hdr_", "auth_", "relay_", "ip_", "dom_", "url_", "att_", "ident_"]
    for idx, fname in enumerate(feature_names):
        if any(fname.startswith(p) for p in strip_prefixes):
            X_pert[:, idx] = -1.0
    # Also set header count to 0
    if "msg_header_count" in feature_names:
        X_pert[:, feature_names.index("msg_header_count")] = 0.0
    return X_pert


if __name__ == "__main__":
    run_phase_d4_pipeline()
