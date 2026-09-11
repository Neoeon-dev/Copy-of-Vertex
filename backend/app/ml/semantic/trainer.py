"""
PyTorch training and fine-tuning pipeline for Phase D3 Semantic Transformer.
"""
from __future__ import annotations

import os
import copy
import time
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from transformers import (
    AutoModelForSequenceClassification,
    PreTrainedTokenizerBase,
    get_linear_schedule_with_warmup,
)
from sklearn.metrics import f1_score


class SemanticTransformerTrainer:
    """
    Supervised fine-tuning manager for DistilBERT email threat classification.
    """

    def __init__(
        self,
        model_name: str = "distilbert-base-uncased",
        num_labels: int = 3,
        device: Optional[str] = None,
        freeze_layers: int = 4,  # Freeze first 4 layers for fast, stable CPU training
        seed: int = 42,
    ) -> None:
        self.model_name = model_name
        self.num_labels = num_labels
        self.freeze_layers = freeze_layers
        self.seed = seed
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")

        # Set seeds for reproducibility
        torch.manual_seed(self.seed)
        np.random.seed(self.seed)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(self.seed)

        # Set CPU threads
        if self.device == "cpu":
            torch.set_num_threads(24)

        # Initialize model
        self.model = AutoModelForSequenceClassification.from_pretrained(
            self.model_name,
            num_labels=self.num_labels,
        )

        # Apply layer freezing if specified
        if self.freeze_layers > 0 and hasattr(self.model, "distilbert"):
            for param in self.model.distilbert.embeddings.parameters():
                param.requires_grad = False
            for i in range(min(self.freeze_layers, len(self.model.distilbert.transformer.layer))):
                for param in self.model.distilbert.transformer.layer[i].parameters():
                    param.requires_grad = False

        self.model.to(self.device)

    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        epochs: int = 3,
        lr: float = 3e-5,
        weight_decay: float = 0.01,
        class_weights: Optional[torch.Tensor] = None,
        warmup_ratio: float = 0.1,
    ) -> Dict[str, Any]:
        """
        Executes supervised fine-tuning with validation monitoring and checkpoint selection.
        """
        trainable_params = [p for p in self.model.parameters() if p.requires_grad]
        optimizer = torch.optim.AdamW(trainable_params, lr=lr, weight_decay=weight_decay)

        total_steps = len(train_loader) * epochs
        warmup_steps = int(total_steps * warmup_ratio)
        scheduler = get_linear_schedule_with_warmup(
            optimizer, num_warmup_steps=warmup_steps, num_training_steps=total_steps
        )

        if class_weights is not None:
            criterion = nn.CrossEntropyLoss(weight=class_weights.to(self.device))
        else:
            criterion = nn.CrossEntropyLoss()

        best_val_f1 = -1.0
        best_model_state = None
        history: List[Dict[str, Any]] = []

        start_time = time.time()
        for epoch in range(1, epochs + 1):
            # Training epoch
            self.model.train()
            train_loss = 0.0
            train_steps = 0

            for batch in train_loader:
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                labels = batch["label"].to(self.device)

                optimizer.zero_grad()
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                loss = criterion(outputs.logits, labels)
                loss.backward()

                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(trainable_params, max_norm=1.0)

                optimizer.step()
                scheduler.step()

                train_loss += loss.item()
                train_steps += 1

            avg_train_loss = train_loss / max(1, train_steps)

            # Validation evaluation
            val_logits, val_labels = self.predict_logits(val_loader)
            val_preds = np.argmax(val_logits, axis=1)
            val_f1 = float(f1_score(val_labels, val_preds, average="macro", zero_division=0))
            val_loss = float(criterion(torch.tensor(val_logits), torch.tensor(val_labels)).item())

            epoch_record = {
                "epoch": epoch,
                "train_loss": round(avg_train_loss, 4),
                "val_loss": round(val_loss, 4),
                "val_macro_f1": round(val_f1, 4),
            }
            history.append(epoch_record)
            print(f"  Epoch {epoch}/{epochs}: Train Loss={avg_train_loss:.4f} | Val Loss={val_loss:.4f} | Val Macro F1={val_f1:.4f}")

            # Checkpoint selection strictly on validation macro F1
            if val_f1 > best_val_f1:
                best_val_f1 = val_f1
                best_model_state = copy.deepcopy(self.model.state_dict())

        # Load best validation checkpoint
        if best_model_state is not None:
            self.model.load_state_dict(best_model_state)

        total_training_time = time.time() - start_time
        return {
            "best_val_macro_f1": round(best_val_f1, 4),
            "total_training_time_sec": round(total_training_time, 2),
            "epochs_trained": epochs,
            "learning_rate": lr,
            "weight_decay": weight_decay,
            "class_weighted": class_weights is not None,
            "history": history,
        }

    def predict_logits(self, dataloader: DataLoader) -> Tuple[np.ndarray, np.ndarray]:
        """
        Extracts raw logits and ground truth labels from a dataloader.
        """
        self.model.eval()
        all_logits = []
        all_labels = []

        with torch.no_grad():
            for batch in dataloader:
                input_ids = batch["input_ids"].to(self.device)
                attention_mask = batch["attention_mask"].to(self.device)
                outputs = self.model(input_ids=input_ids, attention_mask=attention_mask)
                all_logits.append(outputs.logits.cpu().numpy())

                if "label" in batch:
                    all_labels.append(batch["label"].numpy())

        logits_arr = np.vstack(all_logits)
        labels_arr = np.concatenate(all_labels) if all_labels else np.array([])
        return logits_arr, labels_arr

    def save_pretrained(self, save_directory: str, tokenizer: Optional[PreTrainedTokenizerBase] = None) -> None:
        """
        Saves model weights, config, and tokenizer.
        """
        os.makedirs(save_directory, exist_ok=True)
        self.model.save_pretrained(save_directory)
        if tokenizer is not None:
            tok_dir = os.path.join(save_directory, "tokenizer")
            os.makedirs(tok_dir, exist_ok=True)
            tokenizer.save_pretrained(tok_dir)
