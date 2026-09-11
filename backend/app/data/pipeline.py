"""
End-to-End Dataset Pipeline Orchestrator for VERTEX.
Executes the full Phase C workflow:
Acquisition -> Safe Extraction -> Canonical Parsing -> Deduplication -> Group Split -> Telemetry Manifest.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import json
import time
import pandas as pd

from app.data.schema import CanonicalEmailRecord
from app.data.acquisition import acquire_all_approved_datasets, DATASET_CATALOG
from app.data.archive_safety import safe_extract_tar
from app.data.parsers import (
    parse_hf_seven_phishing_parquet,
    parse_spamassassin_raw_eml,
    parse_zenodo_curated_csv,
    parse_validation_emails_csv,
)
from app.data.deduplicator import deduplicate_records, DeduplicationReport
from app.data.splitter import group_aware_stratified_split, SplitResult
from app.data.quality_report import compute_data_quality_report
from app.data.manifest import generate_dataset_manifest
from app.data.checksum import calculate_sha256, calculate_directory_checksums


class VertexDataPipeline:
    def __init__(self, data_root: Path):
        self.data_root = data_root.resolve()
        self.raw_dir = self.data_root / "raw"
        self.interim_dir = self.data_root / "interim"
        self.processed_dir = self.data_root / "processed"
        self.splits_dir = self.processed_dir / "splits"
        self.canonical_dir = self.processed_dir / "canonical"
        self.manifests_dir = self.data_root / "manifests"

        for d in [self.raw_dir, self.interim_dir, self.processed_dir, self.splits_dir, self.canonical_dir, self.manifests_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def step_acquire(self) -> Dict[str, Any]:
        """Downloads all approved datasets into data/raw/."""
        print("[Pipeline Step 1/6] Acquiring approved datasets...")
        return acquire_all_approved_datasets(self.data_root)

    def step_extract_archives(self) -> Dict[str, int]:
        """Safely extracts raw archives into interim directory."""
        print("[Pipeline Step 2/6] Safely extracting raw archives...")
        extracted_counts = {}

        # 1. SpamAssassin easy_ham
        ham_archive = self.raw_dir / "spamassassin" / "20030228_easy_ham.tar.bz2"
        if ham_archive.exists():
            dest = self.interim_dir / "spamassassin" / "easy_ham"
            files = safe_extract_tar(ham_archive, dest)
            extracted_counts["spamassassin_easy_ham"] = len(files)
            print(f"    Extracted {len(files)} easy_ham emails to {dest}")

        # 2. SpamAssassin spam
        spam_archive = self.raw_dir / "spamassassin" / "20030228_spam.tar.bz2"
        if spam_archive.exists():
            dest = self.interim_dir / "spamassassin" / "spam"
            files = safe_extract_tar(spam_archive, dest)
            extracted_counts["spamassassin_spam"] = len(files)
            print(f"    Extracted {len(files)} spam emails to {dest}")

        return extracted_counts

    def step_parse_all_sources(self) -> Tuple[Dict[str, List[CanonicalEmailRecord]], List[CanonicalEmailRecord], Dict[str, int]]:
        """Parses all acquired sources into CanonicalEmailRecord lists."""
        print("[Pipeline Step 3/6] Parsing heterogeneous sources into Canonical Schema...")
        source_records: Dict[str, List[CanonicalEmailRecord]] = {}
        source_rejections: Dict[str, int] = {}
        holdout_records: List[CanonicalEmailRecord] = []

        # 1. HuggingFace Seven Phishing (eval + test partitions)
        hf_eval_p = self.raw_dir / "seven_phishing" / "eval.parquet"
        if hf_eval_p.exists():
            recs = parse_hf_seven_phishing_parquet(hf_eval_p)
            source_records["hf_seven_eval"] = recs
            source_rejections["hf_seven_eval"] = 0
            print(f"    Parsed {len(recs)} records from HF eval.parquet")

        hf_test_p = self.raw_dir / "seven_phishing" / "test.parquet"
        if hf_test_p.exists():
            recs = parse_hf_seven_phishing_parquet(hf_test_p)
            source_records["hf_seven_test"] = recs
            source_rejections["hf_seven_test"] = 0
            print(f"    Parsed {len(recs)} records from HF test.parquet")

        # 2. SpamAssassin RFC 822 emails
        for subfolder, lbl, cat_key in [
            ("easy_ham", "easy_ham", "spamassassin_easy_ham"),
            ("spam", "spam", "spamassassin_spam"),
        ]:
            sa_recs: List[CanonicalEmailRecord] = []
            sa_rej = 0
            folder = self.interim_dir / "spamassassin" / subfolder
            if folder.exists():
                for eml in sorted(folder.rglob("*")):
                    if eml.is_file() and not eml.name.startswith("."):
                        rec = parse_spamassassin_raw_eml(eml, lbl)
                        if rec:
                            sa_recs.append(rec)
                        else:
                            sa_rej += 1
            source_records[cat_key] = sa_recs
            source_rejections[cat_key] = sa_rej
            print(f"    Parsed {len(sa_recs)} RFC 822 records from {cat_key} ({sa_rej} rejected)")

        # 3. Zenodo Curated (Nazario + Nigerian Fraud)
        nazario_p = self.raw_dir / "zenodo_curated" / "Nazario.csv"
        if nazario_p.exists():
            recs = parse_zenodo_curated_csv(nazario_p, "Nazario", threat_type_hint="generic_phish")
            source_records["zenodo_curated_nazario"] = recs
            source_rejections["zenodo_curated_nazario"] = 0
            print(f"    Parsed {len(recs)} records from Zenodo Nazario.csv")

        fraud_p = self.raw_dir / "zenodo_curated" / "Nigerian_Fraud.csv"
        if fraud_p.exists():
            recs = parse_zenodo_curated_csv(fraud_p, "Nigerian_Fraud", threat_type_hint="advance_fee_fraud")
            source_records["zenodo_curated_nigerian_fraud"] = recs
            source_rejections["zenodo_curated_nigerian_fraud"] = 0
            print(f"    Parsed {len(recs)} records from Zenodo Nigerian_Fraud.csv")

        # 4. Zenodo Validation Holdout (100% held out!)
        val_p = self.raw_dir / "validation" / "Phishing_validation_emails.csv"
        if val_p.exists():
            holdout_records = parse_validation_emails_csv(val_p)
            source_records["zenodo_validation_holdout"] = holdout_records
            source_rejections["zenodo_validation_holdout"] = 0
            print(f"    Parsed {len(holdout_records)} independent holdout records from Zenodo 13474746")

        return (source_records, holdout_records, source_rejections)

    def step_deduplicate(
        self,
        all_dev_records: List[CanonicalEmailRecord]
    ) -> Tuple[List[CanonicalEmailRecord], DeduplicationReport, Dict[str, str]]:
        """Deduplicates training/dev records via exact and near-duplicate SimHash."""
        print("[Pipeline Step 4/6] Deduplicating development records...")
        retained, report, record_clusters = deduplicate_records(all_dev_records)
        print(f"    Input: {report.total_input}, Exact duplicates removed: {report.exact_duplicates_removed}, "
              f"Near-duplicates removed: {report.near_duplicates_removed}, Retained: {report.retained_records}")
        return (retained, report, record_clusters)

    def step_split_and_save(
        self,
        retained_records: List[CanonicalEmailRecord],
        record_clusters: Dict[str, str],
        holdout_records: List[CanonicalEmailRecord],
    ) -> Tuple[SplitResult, Dict[str, Path]]:
        """Executes group-aware split and saves canonical Parquet partitions."""
        print("[Pipeline Step 5/6] Partitioning datasets with leakage prevention...")
        split_res, split_map = group_aware_stratified_split(
            records=retained_records,
            record_to_group=record_clusters,
            train_ratio=0.75,
            val_ratio=0.15,
            test_ratio=0.10,
            seed=42,
            holdout_records=holdout_records,
        )

        def _clean_df(df: pd.DataFrame) -> pd.DataFrame:
            string_cols = [
                "record_id", "source_dataset", "source_record_id", "original_label",
                "normalized_label", "threat_type", "subject", "body", "sender",
                "recipient", "cc", "reply_to", "date", "message_id", "raw_file_path",
                "dataset_version", "license", "content_hash", "raw_hash"
            ]
            for col in string_cols:
                if col in df.columns:
                    df[col] = df[col].astype("string")
            return df

        saved_paths = {}
        for split_name, rec_list in split_map.items():
            out_file = self.splits_dir / f"{split_name}.parquet"
            data_dicts = [r.to_dict() for r in rec_list]
            df = _clean_df(pd.DataFrame(data_dicts))
            df.to_parquet(out_file, index=False)
            saved_paths[split_name] = out_file
            print(f"    Saved {split_name}: {len(rec_list)} records -> {out_file.relative_to(self.data_root)}")

        # Also save master canonical corpus
        master_out = self.canonical_dir / "canonical_corpus.parquet"
        all_canonical = retained_records + holdout_records
        df_master = _clean_df(pd.DataFrame([r.to_dict() for r in all_canonical]))
        df_master.to_parquet(master_out, index=False)
        saved_paths["master_canonical"] = master_out
        print(f"    Saved master canonical corpus: {len(all_canonical)} records -> {master_out.relative_to(self.data_root)}")

        return (split_res, saved_paths)

    def step_generate_manifests(
        self,
        acq_report: Dict[str, Any],
        source_records: Dict[str, List[CanonicalEmailRecord]],
        source_rejections: Dict[str, int],
        all_dev_records: List[CanonicalEmailRecord],
        retained_records: List[CanonicalEmailRecord],
        dedup_report: DeduplicationReport,
        split_res: SplitResult,
        holdout_records: List[CanonicalEmailRecord],
    ) -> Dict[str, Any]:
        """Generates machine-readable manifest and data quality report."""
        print("[Pipeline Step 6/6] Generating manifests and data quality reports...")
        
        # 1. Dataset Manifest
        manifest = generate_dataset_manifest(
            acquisition_report=acq_report,
            source_records=source_records,
            source_rejections=source_rejections,
            data_root=self.data_root,
        )
        manifest_path = self.manifests_dir / "dataset_manifest.json"
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2)
        print(f"    Created dataset manifest: {manifest_path.relative_to(self.data_root)}")

        # 2. Data Quality Report
        quality_report = compute_data_quality_report(
            raw_records=all_dev_records,
            deduped_records=retained_records,
            dedup_report=dedup_report,
            split_result=split_res,
            holdout_records=holdout_records,
            rejected_count=sum(source_rejections.values()),
            rejection_reasons={"empty_body_or_corrupted_mime": sum(source_rejections.values())},
        )
        quality_path = self.manifests_dir / "data_quality_report.json"
        with open(quality_path, "w", encoding="utf-8") as f:
            json.dump(quality_report, f, indent=2)
        print(f"    Created data quality report: {quality_path.relative_to(self.data_root)}")

        # 3. Checksums Manifest of raw and processed artifacts
        checksum_dict = {}
        for rel, meta in calculate_directory_checksums(self.raw_dir).items():
            if not rel.endswith(".gitkeep"):
                checksum_dict[f"raw/{rel}"] = meta
        for rel, meta in calculate_directory_checksums(self.splits_dir).items():
            checksum_dict[f"processed/splits/{rel}"] = meta
        for rel, meta in calculate_directory_checksums(self.canonical_dir).items():
            checksum_dict[f"processed/canonical/{rel}"] = meta
        
        checksums_manifest = {
            "generator": "VERTEX-Integrity-System/1.0",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "files": checksum_dict,
        }
        checksum_path = self.manifests_dir / "checksums.json"
        with open(checksum_path, "w", encoding="utf-8") as f:
            json.dump(checksums_manifest, f, indent=2)
        print(f"    Created checksums manifest: {checksum_path.relative_to(self.data_root)}")

        return {
            "manifest": manifest,
            "quality_report": quality_report,
            "checksums": checksums_manifest,
        }

    def run(self) -> Dict[str, Any]:
        """Runs the entire pipeline sequentially."""
        t0 = time.time()
        print("=" * 70)
        print("VERTEX PHASE C DATASET PIPELINE — EXECUTION START")
        print("=" * 70)

        # 1. Acquire
        acq_report = self.step_acquire()

        # 2. Extract
        self.step_extract_archives()

        # 3. Parse
        source_records, holdout_records, source_rejections = self.step_parse_all_sources()

        # Separate development records (to be split) from independent holdout
        all_dev_records = []
        for src_key, recs in source_records.items():
            if src_key != "zenodo_validation_holdout":
                all_dev_records.extend(recs)

        # 4. Deduplicate development records
        retained_records, dedup_report, record_clusters = self.step_deduplicate(all_dev_records)

        # 5. Split and save
        split_res, saved_paths = self.step_split_and_save(
            retained_records=retained_records,
            record_clusters=record_clusters,
            holdout_records=holdout_records,
        )

        # 6. Generate Manifests
        manifests = self.step_generate_manifests(
            acq_report=acq_report,
            source_records=source_records,
            source_rejections=source_rejections,
            all_dev_records=all_dev_records,
            retained_records=retained_records,
            dedup_report=dedup_report,
            split_res=split_res,
            holdout_records=holdout_records,
        )

        elapsed = time.time() - t0
        print("=" * 70)
        print(f"VERTEX PHASE C DATASET PIPELINE COMPLETED SUCCESSFULLY IN {elapsed:.2f}s")
        print("=" * 70)
        return manifests
