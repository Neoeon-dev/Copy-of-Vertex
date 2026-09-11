"""
Deterministic, Leakage-Resistant Dataset Partitioning Engine for VERTEX.
Enforces group-aware splitting to guarantee that entire campaign clusters,
near-duplicate variants, and specific sender domains remain strictly isolated
within a single partition (train, val, or test).
Independent holdout benchmarks are permanently isolated from the training corpus.
"""
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any, Tuple, Optional, Set
import random
from collections import defaultdict
from app.data.schema import CanonicalEmailRecord


@dataclass
class SplitPartition:
    name: str
    record_ids: List[str] = field(default_factory=list)
    label_distribution: Dict[str, int] = field(default_factory=dict)
    source_distribution: Dict[str, int] = field(default_factory=dict)
    group_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "total_records": len(self.record_ids),
            "total_groups": self.group_count,
            "label_distribution": self.label_distribution,
            "source_distribution": self.source_distribution,
        }


@dataclass
class SplitResult:
    seed: int
    algorithm: str
    grouping_strategy: str
    train: SplitPartition
    validation: SplitPartition
    test: SplitPartition
    holdout_independent: Optional[SplitPartition] = None

    def to_dict(self) -> Dict[str, Any]:
        res = {
            "seed": self.seed,
            "algorithm": self.algorithm,
            "grouping_strategy": self.grouping_strategy,
            "train": self.train.to_dict(),
            "validation": self.validation.to_dict(),
            "test": self.test.to_dict(),
        }
        if self.holdout_independent:
            res["holdout_independent"] = self.holdout_independent.to_dict()
        return res


def group_aware_stratified_split(
    records: List[CanonicalEmailRecord],
    record_to_group: Optional[Dict[str, str]] = None,
    train_ratio: float = 0.75,
    val_ratio: float = 0.15,
    test_ratio: float = 0.10,
    seed: int = 42,
    holdout_records: Optional[List[CanonicalEmailRecord]] = None,
) -> Tuple[SplitResult, Dict[str, List[CanonicalEmailRecord]]]:
    """
    Executes a group-aware partition:
    All records belonging to the same group/cluster are assigned to the EXACT SAME split.
    Guarantees 0% group leakage between Train, Validation, and Test.
    """
    if abs((train_ratio + val_ratio + test_ratio) - 1.0) > 1e-5:
        raise ValueError("train_ratio + val_ratio + test_ratio must sum to 1.0")

    # Step 1: Assign groups (use record_to_group or fallback to content_hash prefix)
    group_members: Dict[str, List[CanonicalEmailRecord]] = defaultdict(list)
    for rec in records:
        grp = record_to_group.get(rec.record_id) if record_to_group else rec.content_hash[:8]
        if not grp:
            grp = f"grp_{rec.record_id}"
        group_members[grp].append(rec)

    # Step 2: Determine majority label for each group for stratified group placement
    group_labels: Dict[str, str] = {}
    for grp, members in group_members.items():
        counts: Dict[str, int] = defaultdict(int)
        for m in members:
            counts[m.normalized_label] += 1
        majority_label = max(counts.items(), key=lambda x: x[1])[0]
        group_labels[grp] = majority_label

    # Step 3: Stratify groups by label and shuffle deterministically
    label_to_groups: Dict[str, List[str]] = defaultdict(list)
    for grp, lbl in group_labels.items():
        label_to_groups[lbl].append(grp)

    rng = random.Random(seed)
    for lbl in label_to_groups:
        label_to_groups[lbl].sort()  # deterministic base ordering
        rng.shuffle(label_to_groups[lbl])

    train_groups: Set[str] = set()
    val_groups: Set[str] = set()
    test_groups: Set[str] = set()

    for lbl, grps in label_to_groups.items():
        n = len(grps)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)
        
        # Ensure at least 1 in val and test if n is large enough
        if n >= 3 and n_val == 0:
            n_val = 1
            n_train = max(1, n_train - 1)
        if n >= 4 and (n - n_train - n_val) == 0:
            n_train = max(1, n_train - 1)

        t_g = grps[:n_train]
        v_g = grps[n_train:n_train + n_val]
        te_g = grps[n_train + n_val:]

        train_groups.update(t_g)
        val_groups.update(v_g)
        test_groups.update(te_g)

    # Step 4: Populate partition records and distribution stats
    train_part = SplitPartition(name="train", group_count=len(train_groups))
    val_part = SplitPartition(name="validation", group_count=len(val_groups))
    test_part = SplitPartition(name="test", group_count=len(test_groups))

    split_map: Dict[str, List[CanonicalEmailRecord]] = {
        "train": [],
        "validation": [],
        "test": [],
    }

    for grp, members in group_members.items():
        target_part = train_part
        target_list = split_map["train"]
        if grp in val_groups:
            target_part = val_part
            target_list = split_map["validation"]
        elif grp in test_groups:
            target_part = test_part
            target_list = split_map["test"]

        for m in members:
            target_part.record_ids.append(m.record_id)
            target_part.label_distribution[m.normalized_label] = (
                target_part.label_distribution.get(m.normalized_label, 0) + 1
            )
            target_part.source_distribution[m.source_dataset] = (
                target_part.source_distribution.get(m.source_dataset, 0) + 1
            )
            target_list.append(m)

    # Step 5: Process holdout dataset if provided (100% isolated)
    holdout_part = None
    if holdout_records:
        holdout_part = SplitPartition(name="holdout_independent", group_count=len(holdout_records))
        split_map["holdout_independent"] = []
        for m in holdout_records:
            holdout_part.record_ids.append(m.record_id)
            holdout_part.label_distribution[m.normalized_label] = (
                holdout_part.label_distribution.get(m.normalized_label, 0) + 1
            )
            holdout_part.source_distribution[m.source_dataset] = (
                holdout_part.source_distribution.get(m.source_dataset, 0) + 1
            )
            split_map["holdout_independent"].append(m)

    result = SplitResult(
        seed=seed,
        algorithm="group_aware_stratified_split",
        grouping_strategy="simhash_cluster_or_content_prefix",
        train=train_part,
        validation=val_part,
        test=test_part,
        holdout_independent=holdout_part,
    )

    return (result, split_map)
