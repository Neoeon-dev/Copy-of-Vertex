"""
PyTorch Dataset and collation routines for Phase D3 Semantic Transformer.
"""
from __future__ import annotations

from typing import List, Dict, Any, Optional, Union
import numpy as np
import torch
from torch.utils.data import Dataset
from transformers import PreTrainedTokenizerBase
from sklearn.utils.class_weight import compute_class_weight


class EmailTextDataset(Dataset):
    """
    PyTorch Dataset wrapping preprocessed email texts and target labels.
    """

    def __init__(
        self,
        texts: List[str],
        labels: Optional[Union[List[int], np.ndarray]] = None,
        tokenizer: Optional[PreTrainedTokenizerBase] = None,
        max_length: int = 128,
    ) -> None:
        self.texts = texts
        self.labels = np.array(labels, dtype=np.int64) if labels is not None else None
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self) -> int:
        return len(self.texts)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        text = str(self.texts[idx])
        item: Dict[str, torch.Tensor] = {}

        if self.tokenizer is not None:
            encoding = self.tokenizer(
                text,
                truncation=True,
                max_length=self.max_length,
                padding="max_length",
                return_tensors="pt",
            )
            item["input_ids"] = encoding["input_ids"].squeeze(0)
            item["attention_mask"] = encoding["attention_mask"].squeeze(0)
        else:
            item["text"] = text  # type: ignore

        if self.labels is not None:
            item["label"] = torch.tensor(self.labels[idx], dtype=torch.long)

        return item


def compute_class_weights_tensor(labels: np.ndarray, num_classes: int = 3) -> torch.Tensor:
    """
    Computes balanced class weights normalized for CrossEntropyLoss.
    """
    classes = np.arange(num_classes)
    weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=labels,
    )
    return torch.tensor(weights, dtype=torch.float32)
