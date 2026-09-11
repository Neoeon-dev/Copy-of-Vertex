"""
Exhaustive Automated Test Suite for VERTEX Phase C:
Dataset Acquisition, Safe Normalization, Integrity Checksums,
Deduplication, Group-Aware Splitting, and Independent Validation Isolation.
"""
from pathlib import Path
import tempfile
import tarfile
import zipfile
import pytest
import json
import os

from app.data.schema import (
    CanonicalEmailRecord,
    compute_content_hash,
    VALID_NORMALIZED_LABELS,
    VALID_THREAT_TYPES,
)
from app.data.checksum import (
    calculate_sha256,
    calculate_bytes_sha256,
    generate_checksum_manifest,
    verify_manifest_checksums,
)
from app.data.archive_safety import (
    safe_extract_tar,
    safe_extract_zip,
    ArchiveSecurityError,
)
from app.data.text_normalizer import (
    sanitize_null_bytes,
    normalize_unicode,
    strip_html_safely,
    extract_urls_safely,
    extract_attachment_metadata_inert,
    normalize_email_body_and_subject,
)
from app.data.deduplicator import (
    compute_simhash_64,
    hamming_distance,
    deduplicate_records,
)
from app.data.splitter import group_aware_stratified_split
from app.data.manifest import generate_dataset_manifest
from app.data.quality_report import compute_data_quality_report


# ==============================================================================
# 1. Checksum Generation & Verification Tests
# ==============================================================================

class TestChecksumEngine:
    def test_calculate_bytes_sha256(self):
        data = b"VERTEX Forensic Evidence Payload"
        sha = calculate_bytes_sha256(data)
        assert len(sha) == 64
        # Deterministic check
        assert sha == calculate_bytes_sha256(data)

    def test_file_checksum_and_manifest_verification(self, tmp_path):
        f1 = tmp_path / "file1.txt"
        f2 = tmp_path / "file2.txt"
        f1.write_text("Hello World 1", encoding="utf-8")
        f2.write_text("Hello World 2", encoding="utf-8")

        manifest = generate_checksum_manifest([f1, f2], base_dir=tmp_path)
        assert manifest["file_count"] == 2
        assert "file1.txt" in manifest["files"]
        assert "file2.txt" in manifest["files"]

        # Verify against manifest
        valid, mismatches = verify_manifest_checksums(manifest, base_dir=tmp_path)
        assert valid is True
        assert len(mismatches) == 0

        # Tamper with file1
        f1.write_text("Tampered Content", encoding="utf-8")
        valid_tampered, mismatches_tampered = verify_manifest_checksums(manifest, base_dir=tmp_path)
        assert valid_tampered is False
        assert any("MISMATCH" in m and "file1.txt" in m for m in mismatches_tampered)

    def test_missing_file_detected_in_manifest(self, tmp_path):
        f = tmp_path / "sample.txt"
        f.write_text("Sample", encoding="utf-8")
        manifest = generate_checksum_manifest([f], base_dir=tmp_path)
        f.unlink()
        valid, mismatches = verify_manifest_checksums(manifest, base_dir=tmp_path)
        assert valid is False
        assert any("MISSING" in m for m in mismatches)


# ==============================================================================
# 2. Archive Safety & Hostile Data Protection
# ==============================================================================

class TestArchiveSafety:
    def test_tar_slip_path_traversal_blocked(self, tmp_path):
        bad_tar = tmp_path / "evil.tar"
        with tarfile.open(bad_tar, "w") as tar:
            data = b"root:x:0:0::"
            info = tarfile.TarInfo(name="../../etc/passwd")
            info.size = len(data)
            import io
            tar.addfile(info, fileobj=io.BytesIO(data))

        dest = tmp_path / "extracted"
        with pytest.raises(ArchiveSecurityError, match="Path traversal"):
            safe_extract_tar(bad_tar, dest)

    def test_zip_slip_path_traversal_blocked(self, tmp_path):
        bad_zip = tmp_path / "evil.zip"
        with zipfile.ZipFile(bad_zip, "w") as zf:
            zf.writestr("../../etc/shadow", b"root:x:0:0::")

        dest = tmp_path / "extracted_zip"
        with pytest.raises(ArchiveSecurityError, match="Path traversal"):
            safe_extract_zip(bad_zip, dest)

    def test_safe_tar_extraction_succeeds(self, tmp_path):
        good_tar = tmp_path / "good.tar.gz"
        with tarfile.open(good_tar, "w:gz") as tar:
            data = b"Clean Email RFC 822 content"
            info = tarfile.TarInfo(name="clean_email.eml")
            info.size = len(data)
            import io
            tar.addfile(info, fileobj=io.BytesIO(data))

        dest = tmp_path / "good_extracted"
        extracted = safe_extract_tar(good_tar, dest)
        assert len(extracted) == 1
        assert extracted[0].name == "clean_email.eml"
        assert extracted[0].read_bytes() == b"Clean Email RFC 822 content"

    def test_archive_file_count_limit_exceeded(self, tmp_path):
        bomb_tar = tmp_path / "bomb.tar"
        with tarfile.open(bomb_tar, "w") as tar:
            for i in range(15):
                info = tarfile.TarInfo(name=f"file_{i}.txt")
                info.size = 0
                import io
                tar.addfile(info, fileobj=io.BytesIO(b""))

        dest = tmp_path / "bomb_extracted"
        with pytest.raises(ArchiveSecurityError, match="maximum file count"):
            safe_extract_tar(bomb_tar, dest, max_files=10)


# ==============================================================================
# 3. Content Normalization & Inert Processing
# ==============================================================================

class TestContentNormalizer:
    def test_sanitize_null_bytes(self):
        evil = "Legitimate subject\x00with NUL bytes"
        clean = sanitize_null_bytes(evil)
        assert "\x00" not in clean
        assert "\ufffd" in clean

    def test_unicode_normalization_and_zero_width_strip(self):
        # Text with zero-width space (U+200B) and RTL override (U+202E)
        stealth = "Pay\u200bPal \u202eservice"
        clean = normalize_unicode(stealth)
        assert "\u200b" not in clean
        assert "\u202e" not in clean
        assert "PayPal" in clean

    def test_html_inert_extraction_without_scripts(self):
        html_payload = """
        <html>
        <head><script>alert('malware')</script></head>
        <body>
            <h1>Dear Customer</h1>
            <p>Please update your account at <a href="http://phishing.site/login">Update Now</a>.</p>
            <script>document.location='http://evil.com'</script>
        </body>
        </html>
        """
        plain, urls = strip_html_safely(html_payload)
        assert "alert" not in plain
        assert "document.location" not in plain
        assert "Dear Customer" in plain
        assert "Update Now" in plain
        assert "http://phishing.site/login" in urls

    def test_extract_urls_safely_no_network_calls(self):
        body = "Check https://secure-bank.com/auth and http://192.168.1.1/login or www.malicious.xyz"
        urls = extract_urls_safely(body)
        assert len(urls) == 3
        assert "https://secure-bank.com/auth" in urls
        assert "http://192.168.1.1/login" in urls
        assert "www.malicious.xyz" in urls

    def test_attachment_metadata_inert_extraction(self):
        meta = extract_attachment_metadata_inert(
            filename="../invoice.pdf.exe",
            content_type="application/x-msdos-program",
            raw_payload=b"MZ\x90\x00\x03\x00\x00\x00",
        )
        assert meta["filename"] == "invoice.pdf.exe"
        assert meta["extension"] == ".exe"
        assert meta["is_executable"] is True
        assert meta["size_bytes"] == 8
        assert meta["sha256"] is not None


# ==============================================================================
# 4. Schema & Label Taxonomy Tests
# ==============================================================================

class TestCanonicalSchema:
    def test_valid_record_creation(self):
        rec = CanonicalEmailRecord(
            record_id="test_01",
            source_dataset="test_source",
            source_record_id="123",
            original_label="0",
            normalized_label="legitimate",
            threat_type="clean",
            subject="Quarterly Review",
            body="Hello, please find the quarterly report attached.",
        )
        assert rec.normalized_label == "legitimate"
        assert rec.threat_type == "clean"
        assert rec.content_hash != ""

    def test_invalid_normalized_label_rejected(self):
        with pytest.raises(ValueError, match="Invalid normalized_label"):
            CanonicalEmailRecord(
                record_id="test_02",
                source_dataset="test_source",
                source_record_id="124",
                original_label="malicious",
                normalized_label="bad_label_not_in_taxonomy",
                threat_type="generic_phish",
                subject="Test",
                body="Body text",
            )

    def test_invalid_threat_type_rejected(self):
        with pytest.raises(ValueError, match="Invalid threat_type"):
            CanonicalEmailRecord(
                record_id="test_03",
                source_dataset="test_source",
                source_record_id="125",
                original_label="spam",
                normalized_label="spam",
                threat_type="unknown_threat_dimension",
                subject="Test",
                body="Body text",
            )

    def test_deterministic_content_hash(self):
        h1 = compute_content_hash("Urgent: Action Required", "Please click the link.")
        h2 = compute_content_hash("  urgent: action required  ", "please click the link.  ")
        assert h1 == h2


# ==============================================================================
# 5. Deduplication & SimHash Tests
# ==============================================================================

class TestDeduplicationEngine:
    def test_simhash_and_hamming_distance(self):
        text1 = "Your account has been suspended due to suspicious activity. Click here to verify."
        text2 = "Your account has been suspended due to suspicious activity! Click here to verify immediately."
        text3 = "Completely different email about baking bread and chocolate chip cookies recipe."

        fp1 = compute_simhash_64(text1)
        fp2 = compute_simhash_64(text2)
        fp3 = compute_simhash_64(text3)

        d12 = hamming_distance(fp1, fp2)
        d13 = hamming_distance(fp1, fp3)

        assert d12 <= 10  # Near duplicates have small distance (<= 10 bits difference)
        assert d13 >= 25  # Unrelated emails have large distance (~30-40 bits difference)

    def test_exact_and_near_duplicate_removal(self):
        records = [
            CanonicalEmailRecord(
                record_id="r1", source_dataset="s1", source_record_id="1",
                original_label="phish", normalized_label="phishing", threat_type="generic_phish",
                subject="Account Verification", body="Please verify your bank login at http://fake.com"
            ),
            # Exact duplicate of r1
            CanonicalEmailRecord(
                record_id="r2", source_dataset="s1", source_record_id="2",
                original_label="phish", normalized_label="phishing", threat_type="generic_phish",
                subject="Account Verification", body="Please verify your bank login at http://fake.com"
            ),
            # Near duplicate of r1 (templated campaign)
            CanonicalEmailRecord(
                record_id="r3", source_dataset="s1", source_record_id="3",
                original_label="phish", normalized_label="phishing", threat_type="generic_phish",
                subject="Account Verification!", body="Please verify your bank login at http://fake.com immediately"
            ),
            # Completely distinct clean email
            CanonicalEmailRecord(
                record_id="r4", source_dataset="s2", source_record_id="4",
                original_label="ham", normalized_label="legitimate", threat_type="clean",
                subject="Weekly Staff Meeting", body="Team, the meeting is scheduled for 10 AM tomorrow in Room 4B."
            ),
        ]

        retained, report, clusters = deduplicate_records(records, near_duplicate_threshold=5)
        assert report.total_input == 4
        assert report.exact_duplicates_removed == 1
        assert report.near_duplicates_removed == 1
        assert report.retained_records == 2
        assert len(retained) == 2


# ==============================================================================
# 6. Group-Aware Splitting & Leakage Prevention Tests
# ==============================================================================

class TestSplitterEngine:
    def test_zero_leakage_across_groups(self):
        records = []
        clusters = {}
        # Create 20 groups with 3 emails each (simulating campaigns)
        for g in range(20):
            grp_id = f"campaign_{g}"
            lbl = "phishing" if g % 2 == 0 else "legitimate"
            threat = "generic_phish" if lbl == "phishing" else "clean"
            for m in range(3):
                rec_id = f"rec_{g}_{m}"
                records.append(
                    CanonicalEmailRecord(
                        record_id=rec_id, source_dataset="test_corpus", source_record_id=rec_id,
                        original_label=lbl, normalized_label=lbl, threat_type=threat,
                        subject=f"Campaign {g} message {m}", body=f"Unique body content for campaign {g} member {m}."
                    )
                )
                clusters[rec_id] = grp_id

        split_res, split_map = group_aware_stratified_split(
            records=records,
            record_to_group=clusters,
            train_ratio=0.70,
            val_ratio=0.15,
            test_ratio=0.15,
            seed=42,
        )

        train_ids = set(split_res.train.record_ids)
        val_ids = set(split_res.validation.record_ids)
        test_ids = set(split_res.test.record_ids)

        # 1. Mutually exclusive record IDs
        assert len(train_ids.intersection(val_ids)) == 0
        assert len(train_ids.intersection(test_ids)) == 0
        assert len(val_ids.intersection(test_ids)) == 0

        # 2. Mutually exclusive groups (ZERO LEAKAGE)
        train_groups = {clusters[r] for r in train_ids}
        val_groups = {clusters[r] for r in val_ids}
        test_groups = {clusters[r] for r in test_ids}

        assert len(train_groups.intersection(val_groups)) == 0
        assert len(train_groups.intersection(test_groups)) == 0
        assert len(val_groups.intersection(test_groups)) == 0

    def test_holdout_validation_remains_strictly_isolated(self):
        dev_records = [
            CanonicalEmailRecord(
                record_id="dev_1", source_dataset="train_src", source_record_id="1",
                original_label="ham", normalized_label="legitimate", threat_type="clean",
                subject="Dev ham", body="Dev normal body text."
            ),
            CanonicalEmailRecord(
                record_id="dev_2", source_dataset="train_src", source_record_id="2",
                original_label="spam", normalized_label="spam", threat_type="generic_spam",
                subject="Dev spam", body="Dev spam body text."
            ),
        ]
        holdout = [
            CanonicalEmailRecord(
                record_id="holdout_1", source_dataset="zenodo_validation_holdout", source_record_id="h1",
                original_label="Safe Email", normalized_label="legitimate", threat_type="clean",
                subject="Holdout clean", body="Holdout evaluation text only."
            )
        ]

        split_res, split_map = group_aware_stratified_split(
            records=dev_records,
            train_ratio=0.5,
            val_ratio=0.25,
            test_ratio=0.25,
            seed=42,
            holdout_records=holdout,
        )

        assert "holdout_independent" in split_map
        assert len(split_map["holdout_independent"]) == 1
        assert "holdout_1" not in split_res.train.record_ids
        assert "holdout_1" not in split_res.validation.record_ids
        assert "holdout_1" not in split_res.test.record_ids
