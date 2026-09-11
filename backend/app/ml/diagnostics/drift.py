"""
Feature Distribution and Statistical Drift Analysis Engine for VERTEX ML.
Computes summary distributions, Population Stability Index (PSI), Kolmogorov-Smirnov statistics,
Wasserstein distance, and missing-rate shifts across dataset splits.
"""
from typing import Dict, Any, List, Tuple, Optional
import numpy as np
from scipy.stats import ks_2samp, wasserstein_distance

from app.ml.preprocessing.tabular_loader import TabularDataset
from app.features.registry import get_feature_names, get_feature_by_name


def calculate_feature_summary(values: np.ndarray) -> Dict[str, Any]:
    """Computes statistical summary and missingness metrics for a feature vector."""
    n = len(values)
    if n == 0:
        return {
            "mean": 0.0, "std": 0.0, "median": 0.0, "min": 0.0, "max": 0.0,
            "q25": 0.0, "q75": 0.0, "missing_rate": 0.0, "zero_rate": 0.0, "unique_count": 0,
        }

    # In VERTEX schema, -1.0 is the unobserved/missing sentinel
    missing_count = int(np.sum(values == -1.0))
    zero_count = int(np.sum(values == 0.0))
    missing_rate = float(round(missing_count / n, 4))
    zero_rate = float(round(zero_count / n, 4))

    return {
        "mean": float(round(float(np.mean(values)), 4)),
        "std": float(round(float(np.std(values)), 4)),
        "median": float(round(float(np.median(values)), 4)),
        "min": float(round(float(np.min(values)), 4)),
        "max": float(round(float(np.max(values)), 4)),
        "q25": float(round(float(np.percentile(values, 25)), 4)),
        "q75": float(round(float(np.percentile(values, 75)), 4)),
        "missing_rate": missing_rate,
        "zero_rate": zero_rate,
        "unique_count": int(len(np.unique(values))),
    }


def calculate_psi(expected: np.ndarray, actual: np.ndarray, num_bins: int = 10) -> float:
    """
    Computes Population Stability Index (PSI) with Laplace smoothing.
    Thresholds: PSI < 0.1 (low/stable), 0.1 <= PSI < 0.25 (moderate), PSI >= 0.25 (high/drift).
    """
    if len(expected) == 0 or len(actual) == 0:
        return 0.0

    if np.all(expected == expected[0]) and np.all(actual == actual[0]):
        return 0.0 if expected[0] == actual[0] else 1.0

    percentiles = np.linspace(0, 100, num_bins + 1)
    bin_edges = np.percentile(expected, percentiles)
    bin_edges = np.unique(bin_edges)

    if len(bin_edges) < 2:
        bin_edges = np.array([
            min(expected.min(), actual.min()) - 1e-5,
            max(expected.max(), actual.max()) + 1e-5,
        ])
    else:
        bin_edges[0] = -np.inf
        bin_edges[-1] = np.inf

    exp_counts, _ = np.histogram(expected, bins=bin_edges)
    act_counts, _ = np.histogram(actual, bins=bin_edges)

    eps = 1e-4
    exp_pct = (exp_counts + eps) / (len(expected) + eps * len(exp_counts))
    act_pct = (act_counts + eps) / (len(actual) + eps * len(act_counts))

    psi_val = np.sum((exp_pct - act_pct) * np.log(exp_pct / act_pct))
    return float(round(max(0.0, float(psi_val)), 4))


def calculate_feature_drift(
    train_vals: np.ndarray,
    target_vals: np.ndarray,
    feature_name: str,
) -> Dict[str, Any]:
    """Computes PSI, KS statistic, Wasserstein distance, and missing rate difference."""
    psi = calculate_psi(train_vals, target_vals)

    # KS 2-sample test
    try:
        ks_res = ks_2samp(train_vals, target_vals)
        ks_stat = float(round(float(ks_res.statistic), 4))
        ks_pvalue = float(round(float(ks_res.pvalue), 6))
    except Exception:
        ks_stat = 0.0
        ks_pvalue = 1.0

    # 1D Wasserstein distance
    try:
        wass_dist = float(round(float(wasserstein_distance(train_vals, target_vals)), 4))
    except Exception:
        wass_dist = 0.0

    tr_missing = float(np.mean(train_vals == -1.0))
    tgt_missing = float(np.mean(target_vals == -1.0))
    missing_diff = float(round(tgt_missing - tr_missing, 4))

    # Determine drift level based on standard PSI & KS thresholds
    if psi >= 0.25 or (ks_stat > 0.3 and wass_dist > 1.0):
        drift_level = "high"
    elif psi >= 0.10 or ks_stat > 0.15:
        drift_level = "moderate"
    else:
        drift_level = "low"

    return {
        "feature": feature_name,
        "psi": psi,
        "ks_stat": ks_stat,
        "ks_pvalue": ks_pvalue,
        "wasserstein": wass_dist,
        "train_missing_rate": float(round(tr_missing, 4)),
        "target_missing_rate": float(round(tgt_missing, 4)),
        "missing_rate_diff": missing_diff,
        "drift_level": drift_level,
    }


def compute_distribution_comparison(
    splits: Dict[str, TabularDataset],
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Computes summary distribution across all splits (Train, Val, Test, Holdout).
    Returns nested dictionary and flattened rows for CSV export.
    """
    feature_names = get_feature_names()
    comparison_dict: Dict[str, Any] = {}
    csv_rows: List[Dict[str, Any]] = []

    for idx, fname in enumerate(feature_names):
        fdef = get_feature_by_name(fname)
        group = fdef.group if fdef else "unknown"

        comparison_dict[fname] = {"group": group, "splits": {}}
        row: Dict[str, Any] = {"feature": fname, "group": group}

        for split_name, ds in splits.items():
            if idx < ds.X.shape[1]:
                col_vals = ds.X[:, idx]
                summary = calculate_feature_summary(col_vals)
                comparison_dict[fname]["splits"][split_name] = summary

                for metric, val in summary.items():
                    row[f"{split_name}_{metric}"] = val

        csv_rows.append(row)

    return comparison_dict, csv_rows


def compute_drift_report(
    train_ds: TabularDataset,
    val_ds: TabularDataset,
    test_ds: TabularDataset,
    holdout_ds: TabularDataset,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Computes feature drift across Train vs Val, Train vs Test, and Train vs Holdout.
    Aggregates by feature group and ranks Top 20 drifted features.
    """
    feature_names = train_ds.feature_names
    drift_dict: Dict[str, Any] = {
        "features": {},
        "group_summary": {},
        "top_20_holdout_drift": [],
    }
    csv_rows: List[Dict[str, Any]] = []
    group_psi_tracker: Dict[str, List[float]] = {}

    for idx, fname in enumerate(feature_names):
        fdef = get_feature_by_name(fname)
        group = fdef.group if fdef else "unknown"

        tr_col = train_ds.X[:, idx]
        val_col = val_ds.X[:, idx]
        test_col = test_ds.X[:, idx]
        ho_col = holdout_ds.X[:, idx]

        d_val = calculate_feature_drift(tr_col, val_col, fname)
        d_test = calculate_feature_drift(tr_col, test_col, fname)
        d_ho = calculate_feature_drift(tr_col, ho_col, fname)

        if group not in group_psi_tracker:
            group_psi_tracker[group] = []
        group_psi_tracker[group].append(d_ho["psi"])

        feat_entry = {
            "group": group,
            "train_vs_val": d_val,
            "train_vs_test": d_test,
            "train_vs_holdout": d_ho,
        }
        drift_dict["features"][fname] = feat_entry

        csv_rows.append({
            "feature": fname,
            "group": group,
            "val_psi": d_val["psi"],
            "val_ks": d_val["ks_stat"],
            "test_psi": d_test["psi"],
            "test_ks": d_test["ks_stat"],
            "holdout_psi": d_ho["psi"],
            "holdout_ks": d_ho["ks_stat"],
            "holdout_wasserstein": d_ho["wasserstein"],
            "holdout_missing_diff": d_ho["missing_rate_diff"],
            "holdout_drift_level": d_ho["drift_level"],
        })

    # Top 20 holdout drift features sorted by Holdout PSI
    ranked_ho = sorted(
        csv_rows,
        key=lambda r: (r["holdout_psi"], r["holdout_ks"]),
        reverse=True,
    )
    drift_dict["top_20_holdout_drift"] = ranked_ho[:20]

    # Feature group aggregation
    group_summary = {}
    for group, psis in sorted(group_psi_tracker.items()):
        group_summary[group] = {
            "feature_count": len(psis),
            "mean_holdout_psi": float(round(float(np.mean(psis)), 4)),
            "median_holdout_psi": float(round(float(np.median(psis)), 4)),
            "max_holdout_psi": float(round(float(np.max(psis)), 4)),
            "high_drift_count": int(np.sum(np.array(psis) >= 0.25)),
            "moderate_drift_count": int(np.sum((np.array(psis) >= 0.10) & (np.array(psis) < 0.25))),
            "low_drift_count": int(np.sum(np.array(psis) < 0.10)),
        }
    drift_dict["group_summary"] = group_summary

    return drift_dict, csv_rows
