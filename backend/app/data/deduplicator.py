"""
Deterministic Deduplication Engine for VERTEX.
Implements exact hash deduplication and high-performance SimHash near-duplicate clustering
using block-indexed Locality-Sensitive Hashing (LSH) for O(N) scaling.
Prevents campaign template flooding and tracks deduplication telemetry.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Set, Optional
from collections import defaultdict
import hashlib
import re

from app.data.schema import CanonicalEmailRecord


@dataclass
class DeduplicationReport:
    total_input: int = 0
    exact_duplicates_removed: int = 0
    near_duplicates_removed: int = 0
    retained_records: int = 0
    unique_exact_hashes: int = 0
    near_duplicate_clusters: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_input": self.total_input,
            "exact_duplicates_removed": self.exact_duplicates_removed,
            "near_duplicates_removed": self.near_duplicates_removed,
            "retained_records": self.retained_records,
            "unique_exact_hashes": self.unique_exact_hashes,
            "near_duplicate_clusters": self.near_duplicate_clusters,
            "reduction_ratio": (
                round(1.0 - (self.retained_records / max(1, self.total_input)), 4)
            ),
        }


def compute_simhash_64(text: str) -> int:
    """
    Computes a 64-bit SimHash fingerprint using token shingles (1-word, 2-word).
    Deterministic, robust against word additions/modifications.
    """
    words = re.findall(r"\w+", text.lower())[:80]
    if not words:
        return 0

    features = list(words)
    if len(words) >= 2:
        features.extend(f"{words[i]}_{words[i+1]}" for i in range(len(words) - 1))

    v = [0] * 64
    for f in features:
        h = int(hashlib.md5(f.encode("utf-8")).hexdigest()[:16], 16)
        for i in range(64):
            v[i] += 1 if ((h >> i) & 1) else -1

    fingerprint = 0
    for i in range(64):
        if v[i] > 0:
            fingerprint |= (1 << i)
    return fingerprint


def hamming_distance(h1: int, h2: int) -> int:
    """Calculates bitwise Hamming distance between two 64-bit integers."""
    return bin(h1 ^ h2).count("1")


class SimHashIndex:
    """
    Block-indexed LSH index for 64-bit SimHash.
    Divides 64 bits into 4 blocks of 16 bits.
    Guarantees detecting all pairs with Hamming distance <= 3 with O(1) candidate lookups.
    """
    def __init__(self, max_distance: int = 3, num_blocks: Optional[int] = None):
        self.max_distance = max_distance
        self.num_blocks = num_blocks or max(1, max_distance + 1)
        self.block_size = max(1, 64 // self.num_blocks)
        self.tables: List[Dict[int, List[Tuple[int, str]]]] = [
            defaultdict(list) for _ in range(self.num_blocks)
        ]

    def _get_block(self, fp: int, block_idx: int) -> int:
        shift = block_idx * self.block_size
        mask = (1 << self.block_size) - 1
        return (fp >> shift) & mask

    def find_match(self, fp: int) -> Optional[str]:
        """Finds any existing cluster with Hamming distance <= max_distance."""
        checked_fps: Set[int] = set()
        for i in range(self.num_blocks):
            block_val = self._get_block(fp, i)
            candidates = self.tables[i].get(block_val, [])
            for c_fp, cluster_id in candidates:
                if c_fp in checked_fps:
                    continue
                checked_fps.add(c_fp)
                if hamming_distance(fp, c_fp) <= self.max_distance:
                    return cluster_id
        return None

    def insert(self, fp: int, cluster_id: str):
        """Indexes a cluster representative."""
        entry = (fp, cluster_id)
        for i in range(self.num_blocks):
            block_val = self._get_block(fp, i)
            self.tables[i][block_val].append(entry)


def deduplicate_records(
    records: List[CanonicalEmailRecord],
    near_duplicate_threshold: int = 3,
) -> Tuple[List[CanonicalEmailRecord], DeduplicationReport, Dict[str, str]]:
    """
    Deduplicates a list of CanonicalEmailRecord instances.
    1. Exact hash deduplication (via content_hash).
    2. Near-duplicate clustering (via block-indexed SimHash in O(N)).
    """
    report = DeduplicationReport(total_input=len(records))
    if not records:
        return ([], report, {})

    # Stage 1: Exact deduplication
    seen_exact_hashes: Set[str] = set()
    exact_deduped: List[CanonicalEmailRecord] = []

    for rec in records:
        if rec.content_hash in seen_exact_hashes:
            report.exact_duplicates_removed += 1
            continue
        seen_exact_hashes.add(rec.content_hash)
        exact_deduped.append(rec)

    report.unique_exact_hashes = len(seen_exact_hashes)

    # Stage 2: Near-duplicate clustering using SimHashIndex
    index = SimHashIndex(max_distance=near_duplicate_threshold)
    retained: List[CanonicalEmailRecord] = []
    record_clusters: Dict[str, str] = {}
    cluster_count = 0

    for rec in exact_deduped:
        combined_text = f"{rec.subject or ''} {rec.body}"
        fp = compute_simhash_64(combined_text)

        matched_cluster = index.find_match(fp)
        if matched_cluster is not None:
            record_clusters[rec.record_id] = matched_cluster
            report.near_duplicates_removed += 1
        else:
            new_cluster_id = f"clus_{rec.record_id}"
            cluster_count += 1
            index.insert(fp, new_cluster_id)
            record_clusters[rec.record_id] = new_cluster_id
            retained.append(rec)

    report.near_duplicate_clusters = cluster_count
    report.retained_records = len(retained)

    return (retained, report, record_clusters)
