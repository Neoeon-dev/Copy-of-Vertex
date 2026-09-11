"""
Tokenizer configuration, special token management, and sequence length analysis for Phase D3.
"""
from __future__ import annotations

import os
from typing import List, Dict, Any, Optional
import numpy as np
from transformers import AutoTokenizer, PreTrainedTokenizerBase

TOKENIZER_NAME = "distilbert-base-uncased"
TOKENIZER_VERSION = "distilbert-base-uncased-v1"

SPECIAL_TOKENS = [
    "[SUBJECT]",
    "[BODY]",
    "[URL]",
    "[EMAIL]",
    "[MONEY]",
    "[PHONE]",
    "[EMPTY]",
]


def load_semantic_tokenizer(
    pretrained_model_name: str = TOKENIZER_NAME,
    add_special_tokens: bool = True,
) -> PreTrainedTokenizerBase:
    """
    Loads and configures the DistilBERT tokenizer with domain special tokens.
    """
    tokenizer = AutoTokenizer.from_pretrained(pretrained_model_name)
    if add_special_tokens:
        special_tokens_dict = {"additional_special_tokens": SPECIAL_TOKENS}
        tokenizer.add_special_tokens(special_tokens_dict)
    return tokenizer


def analyze_sequence_lengths(
    texts: List[str],
    tokenizer: PreTrainedTokenizerBase,
    max_lengths: Optional[List[int]] = None,
) -> Dict[str, Any]:
    """
    Computes empirical token length distribution and truncation rates across specified max lengths.
    """
    if max_lengths is None:
        max_lengths = [64, 128, 256, 512]

    # Tokenize without truncation to measure natural distribution
    lengths = []
    for text in texts:
        tokens = tokenizer.encode(text, truncation=False, add_special_tokens=True)
        lengths.append(len(tokens))

    arr = np.array(lengths, dtype=np.int32)
    stats: Dict[str, Any] = {
        "sample_count": len(texts),
        "mean_length": float(np.mean(arr)),
        "std_length": float(np.std(arr)),
        "median_length": float(np.median(arr)),
        "min_length": int(np.min(arr)),
        "max_length": int(np.max(arr)),
        "p25": float(np.percentile(arr, 25)),
        "p50": float(np.percentile(arr, 50)),
        "p75": float(np.percentile(arr, 75)),
        "p90": float(np.percentile(arr, 90)),
        "p95": float(np.percentile(arr, 95)),
        "p99": float(np.percentile(arr, 99)),
        "truncation_rates": {},
    }

    for ml in max_lengths:
        truncated_count = int(np.sum(arr > ml))
        truncation_pct = float(truncated_count / len(arr) * 100.0)
        stats["truncation_rates"][str(ml)] = {
            "truncated_count": truncated_count,
            "truncation_pct": round(truncation_pct, 2),
            "retained_pct": round(100.0 - truncation_pct, 2),
        }

    return stats


def head_tail_truncate(
    input_ids: List[int],
    max_length: int,
    cls_token_id: int,
    sep_token_id: int,
) -> List[int]:
    """
    Preserves the beginning (head) and ending (tail) of a sequence if it exceeds max_length.
    """
    if len(input_ids) <= max_length:
        return input_ids

    budget = max_length - 2  # reserve space for [CLS] and [SEP]
    head_len = budget // 2
    tail_len = budget - head_len

    head_tokens = input_ids[1 : 1 + head_len]
    tail_tokens = input_ids[-1 - tail_len : -1]

    return [cls_token_id] + head_tokens + tail_tokens + [sep_token_id]
