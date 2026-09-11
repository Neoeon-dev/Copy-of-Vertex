"""
VERTEX Forensic Feature Engineering CLI.
Extracts versioned forensic feature sets from dataset splits, exports parquet datasets,
and computes feature quality manifests.
"""
from typing import List, Dict, Any, Optional
import argparse
import os
import sys
import json
import time
import math
from datetime import datetime, timezone
from concurrent.futures import ProcessPoolExecutor, as_completed

import pyarrow as pa
import pyarrow.parquet as pq

from app.features.extractor import ForensicFeatureExtractor
from app.features.registry import (
    get_feature_names,
    get_feature_registry,
    export_feature_schema_json,
)
from app.features.version import FORENSIC_FEATURE_VERSION, FEATURE_EXTRACTOR_VERSION


def _process_chunk(chunk_rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Worker function for batch extraction."""
    extractor = ForensicFeatureExtractor()
    results = []
    for row in chunk_rows:
        vec = extractor.extract_from_canonical_record(row)
        results.append(vec.to_flat_dict())
    return results


def extract_features_for_split(
    input_parquet: str,
    output_parquet: str,
    batch_size: int = 1000,
    max_workers: int = 4,
) -> Dict[str, Any]:
    """
    Extracts features for a split parquet file and saves to output parquet.
    """
    print(f"\n[+] Extracting features from: {input_parquet}")
    start_time = time.time()

    if not os.path.exists(input_parquet):
        raise FileNotFoundError(f"Input split not found: {input_parquet}")

    table = pq.read_table(input_parquet)
    total_rows = table.num_rows
    print(f"    Loaded {total_rows} records. Batch size: {batch_size}, Workers: {max_workers}")

    rows = table.to_pylist()
    chunks = [rows[i : i + batch_size] for i in range(0, total_rows, batch_size)]

    all_extracted: List[Dict[str, Any]] = []
    processed_count = 0

    if max_workers <= 1:
        extractor = ForensicFeatureExtractor()
        for idx, row in enumerate(rows):
            vec = extractor.extract_from_canonical_record(row)
            all_extracted.append(vec.to_flat_dict())
            if (idx + 1) % 2000 == 0 or (idx + 1) == total_rows:
                pct = ((idx + 1) / total_rows) * 100
                print(f"    Processed {idx + 1}/{total_rows} ({pct:.1f}%)")
    else:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            future_to_idx = {executor.submit(_process_chunk, chunk): idx for idx, chunk in enumerate(chunks)}
            ordered_chunks: Dict[int, List[Dict[str, Any]]] = {}

            for future in as_completed(future_to_idx):
                idx = future_to_idx[future]
                res = future.result()
                ordered_chunks[idx] = res
                processed_count += len(res)
                pct = (processed_count / total_rows) * 100
                print(f"    Processed {processed_count}/{total_rows} ({pct:.1f}%)")

            for idx in sorted(ordered_chunks.keys()):
                all_extracted.extend(ordered_chunks[idx])

    # Convert to PyArrow Table and save
    out_table = pa.Table.from_pylist(all_extracted)
    os.makedirs(os.path.dirname(os.path.abspath(output_parquet)), exist_ok=True)
    pq.write_table(out_table, output_parquet, compression="zstd")

    duration = time.time() - start_time
    rate = total_rows / duration if duration > 0 else 0
    size_mb = os.path.getsize(output_parquet) / (1024 * 1024)

    print(f"    Completed in {duration:.2f}s ({rate:.1f} rows/s). Output size: {size_mb:.2f} MB")
    print(f"    Saved to: {output_parquet}")

    return {
        "split": os.path.basename(input_parquet),
        "total_records": total_rows,
        "features_count": len(get_feature_names()),
        "duration_sec": round(duration, 2),
        "rate_rows_per_sec": round(rate, 1),
        "output_file": output_parquet,
        "file_size_mb": round(size_mb, 2),
    }


def generate_feature_quality_report(
    feature_files: Dict[str, str],
    output_json: str,
) -> Dict[str, Any]:
    """
    Computes statistical data quality, missing rates, and zero-variance checks
    across extracted feature parquet files.
    """
    print(f"\n[+] Generating Feature Quality Report...")
    feature_names = get_feature_names()
    split_summaries = {}

    for split_name, fpath in feature_files.items():
        if not os.path.exists(fpath):
            print(f"    [!] Skipping missing feature file: {fpath}")
            continue

        print(f"    Analyzing {split_name} ({fpath})...")
        table = pq.read_table(fpath)
        num_rows = table.num_rows

        feature_stats = {}
        zero_variance_features = []

        for fname in feature_names:
            col = table.column(fname)
            values = col.to_pylist()
            non_null_vals = [v for v in values if v is not None and not (isinstance(v, float) and math.isnan(v))]

            # In forensic telemetry, -1.0 designates unobserved/unavailable evidence
            missing_count = sum(1 for v in non_null_vals if v == -1.0) + (num_rows - len(non_null_vals))
            missing_rate = round(missing_count / num_rows, 4) if num_rows > 0 else 0.0

            valid_vals = [v for v in non_null_vals if v != -1.0]

            if valid_vals:
                min_v = float(min(valid_vals))
                max_v = float(max(valid_vals))
                mean_v = float(sum(valid_vals) / len(valid_vals))
                if min_v == max_v:
                    zero_variance_features.append(fname)
            else:
                min_v = -1.0
                max_v = -1.0
                mean_v = -1.0

            feature_stats[fname] = {
                "missing_rate": missing_rate,
                "min": round(min_v, 4),
                "max": round(max_v, 4),
                "mean": round(mean_v, 4),
            }

        split_summaries[split_name] = {
            "num_rows": num_rows,
            "feature_count": len(feature_names),
            "zero_variance_feature_count": len(zero_variance_features),
            "zero_variance_features": zero_variance_features,
            "sample_feature_stats": {
                k: feature_stats[k]
                for k in list(feature_stats.keys())[:15]
            },
        }

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "feature_version": FORENSIC_FEATURE_VERSION,
        "extractor_version": FEATURE_EXTRACTOR_VERSION,
        "total_registered_features": len(feature_names),
        "feature_registry_names": feature_names,
        "splits": split_summaries,
    }

    os.makedirs(os.path.dirname(os.path.abspath(output_json)), exist_ok=True)
    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"    Quality report saved to: {output_json}")
    return report


def main():
    parser = argparse.ArgumentParser(description="VERTEX Forensic Feature Extraction CLI")
    parser.add_argument(
        "--splits-dir",
        type=str,
        default="data/processed/splits",
        help="Directory containing input split parquet files",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="data/processed/features",
        help="Directory to save output feature parquet files",
    )
    parser.add_argument(
        "--manifest-dir",
        type=str,
        default="data/manifests",
        help="Directory to save quality report and schema",
    )
    parser.add_argument(
        "--split",
        type=str,
        choices=["train", "validation", "test", "holdout_independent", "all"],
        default="all",
        help="Specific split to process or 'all'",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=4,
        help="Number of parallel worker processes",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Batch size per worker chunk",
    )

    args = parser.parse_args()

    split_targets = (
        ["train", "validation", "test", "holdout_independent"]
        if args.split == "all"
        else [args.split]
    )

    # 1. Export Registry Schema JSON
    schema_path = os.path.join(args.manifest_dir, "feature_registry_schema.json")
    os.makedirs(args.manifest_dir, exist_ok=True)
    with open(schema_path, "w", encoding="utf-8") as f:
        f.write(export_feature_schema_json())
    print(f"[+] Exported schema definition ({len(get_feature_names())} features) to {schema_path}")

    # 2. Extract Features
    output_files: Dict[str, str] = {}
    for sp in split_targets:
        in_p = os.path.join(args.splits_dir, f"{sp}.parquet")
        out_p = os.path.join(args.output_dir, f"{sp}_features.parquet")
        if os.path.exists(in_p):
            extract_features_for_split(
                input_parquet=in_p,
                output_parquet=out_p,
                batch_size=args.batch_size,
                max_workers=args.workers,
            )
            output_files[sp] = out_p
        else:
            print(f"[!] Split file {in_p} not found, skipping.")

    # 3. Generate Quality Report
    report_path = os.path.join(args.manifest_dir, "feature_quality_report.json")
    generate_feature_quality_report(output_files, report_path)


if __name__ == "__main__":
    main()
