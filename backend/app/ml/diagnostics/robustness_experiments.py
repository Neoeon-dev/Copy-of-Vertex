"""
Robustness Experiments Engine for VERTEX ML.
Executes Binary Threat Diagnostic, Phishing vs Legitimate Diagnostic,
Feature Subset Robustness, Leave-One-Source-Out (LOSO), Calibration Shift,
Threshold Robustness, and Offline Feature Perturbation Sensitivity.
"""
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
import warnings
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    precision_recall_curve,
    auc,
    brier_score_loss,
    confusion_matrix,
    log_loss,
)
from lightgbm import LGBMClassifier, early_stopping, log_evaluation

from app.ml.preprocessing.tabular_loader import TabularDataset
from app.ml.version import TARGET_CLASSES, LABEL_TO_INT
from app.ml.evaluation.metrics import calculate_expected_calibration_error, calculate_multiclass_brier_score
from app.features.registry import FEATURE_REGISTRY, get_feature_by_name


def evaluate_binary_metrics(y_true: np.ndarray, y_prob_pos: np.ndarray) -> Dict[str, Any]:
    """Computes comprehensive binary classification metrics."""
    y_pred = (y_prob_pos >= 0.5).astype(int)
    acc = float(round(accuracy_score(y_true, y_pred), 4))
    prec, rec, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    
    try:
        roc = float(round(roc_auc_score(y_true, y_prob_pos), 4))
    except Exception:
        roc = 0.0

    try:
        p_c, r_c, _ = precision_recall_curve(y_true, y_prob_pos)
        pr_auc = float(round(auc(r_c, p_c), 4))
    except Exception:
        pr_auc = 0.0

    brier = float(round(brier_score_loss(y_true, y_prob_pos), 4))
    cm = confusion_matrix(y_true, y_pred).tolist()

    return {
        "accuracy": acc,
        "precision": float(round(prec, 4)),
        "recall": float(round(rec, 4)),
        "f1": float(round(f1, 4)),
        "pr_auc": pr_auc,
        "roc_auc": roc,
        "brier_score": brier,
        "confusion_matrix": cm,
    }


def run_binary_threat_diagnostic(
    train_ds: TabularDataset,
    val_ds: TabularDataset,
    test_ds: TabularDataset,
    holdout_ds: TabularDataset,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Diagnostic Experiment: Legitimate (0) vs Threat (1 = Spam + Phishing).
    Trained on Train, tuned on Val, evaluated on Test, and frozen evaluated on Holdout.
    """
    # Map classes: 0 -> 0 (Legitimate), 1,2 -> 1 (Threat)
    y_tr_bin = (train_ds.y > 0).astype(int)
    y_val_bin = (val_ds.y > 0).astype(int)
    y_test_bin = (test_ds.y > 0).astype(int)
    y_ho_bin = (holdout_ds.y > 0).astype(int)

    clf = LGBMClassifier(
        objective="binary",
        learning_rate=0.05,
        n_estimators=300,
        num_leaves=31,
        random_state=random_state,
        n_jobs=-1,
        verbose=-1,
    )

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore")
        clf.fit(
            train_ds.X, y_tr_bin,
            eval_set=[(val_ds.X, y_val_bin)],
            callbacks=[early_stopping(20, verbose=False), log_evaluation(0)],
        )

    test_probs = clf.predict_proba(test_ds.X)[:, 1]
    ho_probs = clf.predict_proba(holdout_ds.X)[:, 1]

    test_m = evaluate_binary_metrics(y_test_bin, test_probs)
    ho_m = evaluate_binary_metrics(y_ho_bin, ho_probs)

    return {
        "description": "Binary Threat Diagnostic: Legitimate (0) vs Threat (1 = Spam + Phishing)",
        "test_metrics": test_m,
        "holdout_metrics": ho_m,
        "generalization_gap_f1": float(round(test_m["f1"] - ho_m["f1"], 4)),
        "generalization_gap_pr_auc": float(round(test_m["pr_auc"] - ho_m["pr_auc"], 4)),
    }


def run_phishing_vs_legitimate_diagnostic(
    train_ds: TabularDataset,
    val_ds: TabularDataset,
    test_ds: TabularDataset,
    holdout_ds: TabularDataset,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Diagnostic Experiment: Legitimate (0) vs Phishing (1), excluding Spam.
    Trained on Train, tuned on Val, evaluated on Test, and frozen evaluated on Holdout.
    """
    legit_idx = LABEL_TO_INT["legitimate"]
    phish_idx = LABEL_TO_INT["phishing"]

    # Filter subsets (exclude spam)
    def filter_split(ds: TabularDataset) -> Tuple[np.ndarray, np.ndarray]:
        mask = (ds.y == legit_idx) | (ds.y == phish_idx)
        X_sub = ds.X[mask]
        y_sub = (ds.y[mask] == phish_idx).astype(int)
        return X_sub, y_sub

    X_tr, y_tr = filter_split(train_ds)
    X_val, y_val = filter_split(val_ds)
    X_test, y_test = filter_split(test_ds)
    X_ho, y_ho = filter_split(holdout_ds)

    clf = LGBMClassifier(
        objective="binary",
        learning_rate=0.05,
        n_estimators=300,
        num_leaves=31,
        random_state=random_state,
        n_jobs=-1,
        verbose=-1,
    )

    with warnings.catch_warnings():
        warnings.filterwarnings("ignore")
        clf.fit(
            X_tr, y_tr,
            eval_set=[(X_val, y_val)],
            callbacks=[early_stopping(20, verbose=False), log_evaluation(0)],
        )

    test_probs = clf.predict_proba(X_test)[:, 1]
    ho_probs = clf.predict_proba(X_ho)[:, 1]

    test_m = evaluate_binary_metrics(y_test, test_probs)
    ho_m = evaluate_binary_metrics(y_ho, ho_probs)

    return {
        "description": "Phishing vs Legitimate Diagnostic (Excluding Spam): Legitimate (0) vs Phishing (1)",
        "test_metrics": test_m,
        "holdout_metrics": ho_m,
        "generalization_gap_f1": float(round(test_m["f1"] - ho_m["f1"], 4)),
        "generalization_gap_pr_auc": float(round(test_m["pr_auc"] - ho_m["pr_auc"], 4)),
    }


def run_feature_subset_robustness_analysis(
    train_ds: TabularDataset,
    val_ds: TabularDataset,
    test_ds: TabularDataset,
    holdout_ds: TabularDataset,
    holdout_psi_dict: Dict[str, float],
    feature_importances: Dict[str, float],
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Evaluates 7 diagnostic feature subset configurations across Test and Holdout.
    Measures which evidence families generalize robustly without severe performance collapse.
    """
    feature_names = train_ds.feature_names
    feat_map = {f.name: f for f in FEATURE_REGISTRY}

    # Define subsets
    subsets: Dict[str, List[str]] = {
        "A_all_125_features": feature_names,
        "B_low_drift_features": [f for f in feature_names if holdout_psi_dict.get(f, 0.0) < 0.25],
        "C_network_header_auth": [
            f for f in feature_names
            if feat_map.get(f) and feat_map[f].group in [
                "authentication_signals", "identity_consistency", "relay_path", "ip_infrastructure", "header_signals"
            ]
        ],
        "D_domain_url_content": [
            f for f in feature_names
            if feat_map.get(f) and feat_map[f].group in ["domain_signals", "url_signals", "content_structure"]
        ],
        "E_message_content_bec": [
            f for f in feature_names
            if feat_map.get(f) and feat_map[f].group in ["message_basics", "content_structure", "bec_phish_signals"]
        ],
        "F_low_drift_forensic_only": [
            f for f in feature_names
            if holdout_psi_dict.get(f, 0.0) < 0.25 and feat_map.get(f) and feat_map[f].group in [
                "authentication_signals", "url_signals", "domain_signals", "bec_phish_signals"
            ]
        ],
        "G_top_20_predictive": [
            f for f, _ in sorted(feature_importances.items(), key=lambda x: x[1], reverse=True)[:20]
            if f in feature_names
        ],
    }

    results = {}

    for subset_name, subset_feats in subsets.items():
        if len(subset_feats) < 3:
            continue

        indices = [train_ds.feature_names.index(f) for f in subset_feats]
        X_tr = train_ds.X[:, indices]
        X_val = val_ds.X[:, indices]
        X_test = test_ds.X[:, indices]
        X_ho = holdout_ds.X[:, indices]

        clf = LGBMClassifier(
            objective="multiclass",
            num_class=3,
            learning_rate=0.05,
            n_estimators=250,
            num_leaves=31,
            random_state=random_state,
            n_jobs=-1,
            verbose=-1,
        )

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            clf.fit(
                X_tr, train_ds.y,
                eval_set=[(X_val, val_ds.y)],
                callbacks=[early_stopping(20, verbose=False), log_evaluation(0)],
            )

        test_probs = clf.predict_proba(X_test)
        ho_probs = clf.predict_proba(X_ho)

        test_preds = np.argmax(test_probs, axis=1)
        ho_preds = np.argmax(ho_probs, axis=1)

        test_acc = float(round(accuracy_score(test_ds.y, test_preds), 4))
        test_f1 = float(round(precision_recall_fscore_support(test_ds.y, test_preds, average="macro", zero_division=0)[2], 4))

        ho_acc = float(round(accuracy_score(holdout_ds.y, ho_preds), 4))
        ho_f1 = float(round(precision_recall_fscore_support(holdout_ds.y, ho_preds, average="macro", zero_division=0)[2], 4))

        # Phishing metrics
        phish_idx = LABEL_TO_INT["phishing"]
        ho_phish_rec = float(round(float(np.sum((holdout_ds.y == phish_idx) & (ho_preds == phish_idx)) / 1000.0), 4))
        ho_phish_prec = float(round(float(np.sum((holdout_ds.y == phish_idx) & (ho_preds == phish_idx)) / max(np.sum(ho_preds == phish_idx), 1)), 4))

        results[subset_name] = {
            "feature_count": len(subset_feats),
            "test_accuracy": test_acc,
            "test_macro_f1": test_f1,
            "holdout_accuracy": ho_acc,
            "holdout_macro_f1": ho_f1,
            "holdout_phishing_recall": ho_phish_rec,
            "holdout_phishing_precision": ho_phish_prec,
            "generalization_gap_f1": float(round(test_f1 - ho_f1, 4)),
        }

    return results


def run_leave_one_source_out(
    train_ds: TabularDataset,
    val_ds: TabularDataset,
    major_sources: Optional[List[str]] = None,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Performs Leave-One-Source-Out (LOSO) cross-domain validation for major sources.
    Trains on N-1 sources, evaluates on held-out source X.
    """
    if major_sources is None:
        major_sources = [
            "hf_seven_phishing/TREC-05",
            "hf_seven_phishing/CEAS-08",
            "hf_seven_phishing/Enron",
            "zenodo_8339691/Nazario",
        ]

    sources_arr = np.array(train_ds.source_datasets)
    val_sources_arr = np.array(val_ds.source_datasets)
    results = {}

    for src in major_sources:
        tr_mask = (sources_arr != src)
        test_mask = (val_sources_arr == src)

        if np.sum(tr_mask) == 0 or np.sum(test_mask) == 0:
            continue

        X_tr = train_ds.X[tr_mask]
        y_tr = train_ds.y[tr_mask]

        X_eval = val_ds.X[test_mask]
        y_eval = val_ds.y[test_mask]

        clf = LGBMClassifier(
            objective="multiclass",
            num_class=3,
            learning_rate=0.08,
            n_estimators=150,
            num_leaves=31,
            random_state=random_state,
            n_jobs=-1,
            verbose=-1,
        )

        with warnings.catch_warnings():
            warnings.filterwarnings("ignore")
            clf.fit(X_tr, y_tr)

        preds = clf.predict(X_eval)
        probs = clf.predict_proba(X_eval)

        acc = float(round(accuracy_score(y_eval, preds), 4))
        macro_f1 = float(round(precision_recall_fscore_support(y_eval, preds, average="macro", zero_division=0)[2], 4))

        results[src] = {
            "held_out_samples": int(len(y_eval)),
            "accuracy": acc,
            "macro_f1": macro_f1,
            "classes_present": [int(c) for c in sorted(set(y_eval))],
        }

    return results


def run_threshold_shift_analysis(
    model: Any,
    test_ds: TabularDataset,
    holdout_ds: TabularDataset,
    thresholds: Optional[List[float]] = None,
) -> Dict[str, Any]:
    """
    Compares decision threshold trade-offs on Test vs Holdout to measure threshold instability.
    """
    if thresholds is None:
        thresholds = [0.05, 0.20, 0.50, 0.80, 0.95]

    phish_idx = LABEL_TO_INT["phishing"]
    test_phish_probs = model.predict_proba(test_ds.X)[:, phish_idx]
    ho_phish_probs = model.predict_proba(holdout_ds.X)[:, phish_idx]

    y_test_bin = (test_ds.y == phish_idx).astype(int)
    y_ho_bin = (holdout_ds.y == phish_idx).astype(int)

    comparison = []

    for t in thresholds:
        test_pred = (test_phish_probs >= t).astype(int)
        ho_pred = (ho_phish_probs >= t).astype(int)

        t_tp = int(np.sum((y_test_bin == 1) & (test_pred == 1)))
        t_fp = int(np.sum((y_test_bin == 0) & (test_pred == 1)))
        t_fn = int(np.sum((y_test_bin == 1) & (test_pred == 0)))
        t_tn = int(np.sum((y_test_bin == 0) & (test_pred == 0)))

        h_tp = int(np.sum((y_ho_bin == 1) & (ho_pred == 1)))
        h_fp = int(np.sum((y_ho_bin == 0) & (ho_pred == 1)))
        h_fn = int(np.sum((y_ho_bin == 1) & (ho_pred == 0)))
        h_tn = int(np.sum((y_ho_bin == 0) & (ho_pred == 0)))

        t_prec = float(round(t_tp / max(t_tp + t_fp, 1), 4))
        t_rec = float(round(t_tp / max(t_tp + t_fn, 1), 4))
        t_fpr = float(round(t_fp / max(t_fp + t_tn, 1), 4))

        h_prec = float(round(h_tp / max(h_tp + h_fp, 1), 4))
        h_rec = float(round(h_tp / max(h_tp + h_fn, 1), 4))
        h_fpr = float(round(h_fp / max(h_fp + h_tn, 1), 4))

        comparison.append({
            "threshold": t,
            "test": {"precision": t_prec, "recall": t_rec, "fpr": t_fpr},
            "holdout": {"precision": h_prec, "recall": h_rec, "fpr": h_fpr},
            "precision_drop": float(round(t_prec - h_prec, 4)),
            "fpr_increase": float(round(h_fpr - t_fpr, 4)),
        })

    return {"threshold_shifts": comparison}


def run_offline_perturbation_sensitivity(
    model: Any,
    test_ds: TabularDataset,
    sample_size: int = 500,
    random_state: int = 42,
) -> Dict[str, Any]:
    """
    Performs safe offline feature perturbations on a sample to quantify model dependence.
    """
    feature_names = test_ds.feature_names
    feat_idx = {f: i for i, f in enumerate(feature_names)}

    np.random.seed(random_state)
    indices = np.random.choice(len(test_ds.y), size=min(sample_size, len(test_ds.y)), replace=False)
    X_sample = test_ds.X[indices].copy()

    base_probs = model.predict_proba(X_sample)
    base_preds = np.argmax(base_probs, axis=1)
    base_phish_prob = base_probs[:, 2]

    perturbations = {
        "strip_urls": [("url_count", 0.0), ("url_suspicious_count", 0.0), ("url_domain_entropy", 0.0)],
        "strip_html": [("msg_has_html", 0.0)],
        "zero_bec_tokens": [("bec_urgency_words_count", 0.0), ("bec_action_words_count", 0.0), ("bec_login_terms_count", 0.0)],
        "remove_auth_headers": [("auth_spf_pass", -1.0), ("auth_dkim_pass", -1.0), ("auth_dmarc_pass", -1.0)],
    }

    results = {}

    for p_name, modifications in perturbations.items():
        X_perturbed = X_sample.copy()
        for col_name, new_val in modifications:
            if col_name in feat_idx:
                X_perturbed[:, feat_idx[col_name]] = new_val

        pert_probs = model.predict_proba(X_perturbed)
        pert_preds = np.argmax(pert_probs, axis=1)
        pert_phish_prob = pert_probs[:, 2]

        flip_count = int(np.sum(base_preds != pert_preds))
        flip_rate = float(round(flip_count / len(indices), 4))
        mean_phish_delta = float(round(float(np.mean(pert_phish_prob - base_phish_prob)), 4))

        results[p_name] = {
            "prediction_flip_count": flip_count,
            "prediction_flip_rate": flip_rate,
            "mean_phishing_probability_shift": mean_phish_delta,
        }

    return results
