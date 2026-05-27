#!/usr/bin/env python3
"""
train.py — Train Secret Squirrel CNN models.

Training strategy:
  1. Knowledge distillation: use soft labels from a pre-trained teacher 
     (if available) or just hard labels from the dataset.
  2. Focal loss to handle class imbalance.
  3. Cosine LR schedule with warmup.
  4. Early stopping on validation F1.
  5. Best checkpoint saved by F1.

Usage:
    uv run python train.py --tier tiny --epochs 20
    uv run python train.py --tier large --epochs 30
"""

import argparse
import json
import os
import time
from pathlib import Path

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader, Dataset
from torch.optim import AdamW
from torch.optim.lr_scheduler import OneCycleLR

try:
    from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

from models import build_tiny, build_large, ALPHABET_SIZE

# ─── Paths ────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent
DATA_DIR = ROOT / "data"
CKPT_DIR = ROOT / "checkpoints"
CKPT_DIR.mkdir(exist_ok=True)

# ─── Tokenizer (mirrors Rust char_to_idx exactly) ─────────────────────────────

UNK_IDX = 99

def char_to_idx(c: int) -> int:
    """Map a single byte value to its embedding index. Mirrors cnn.rs::char_to_idx."""
    if ord('a') <= c <= ord('z'):
        return c - ord('a')
    elif ord('A') <= c <= ord('Z'):
        return c - ord('A') + 26
    elif ord('0') <= c <= ord('9'):
        return c - ord('0') + 52
    elif c == ord(' '):
        return 86
    elif 33 <= c <= 47:
        return c - 33 + 62
    elif 58 <= c <= 64:
        return c - 58 + 77
    elif 91 <= c <= 96:
        return c - 91 + 84
    elif 123 <= c <= 126:
        return c - 123 + 90
    else:
        return UNK_IDX


def tokenize(text: str, max_len: int = 256) -> list[int]:
    """Tokenize a string to a fixed-length list of indices."""
    tokens = [char_to_idx(b) for b in text.encode('utf-8', errors='replace')[:max_len]]
    # Pad with zeros
    tokens.extend([0] * (max_len - len(tokens)))
    return tokens


# ─── Dataset ──────────────────────────────────────────────────────────────────

class CredentialDataset(Dataset):
    def __init__(self, path: Path, max_len: int = 256):
        self.samples: list[tuple[list[int], int]] = []
        with open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                text = obj.get("text", "")
                label = int(obj.get("label", 0))
                tokens = tokenize(text, max_len)
                self.samples.append((tokens, label))

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int):
        tokens, label = self.samples[idx]
        return torch.tensor(tokens, dtype=torch.long), torch.tensor(label, dtype=torch.long)


# ─── Focal Loss (handles class imbalance better than CE) ──────────────────────

class FocalLoss(nn.Module):
    """
    Focal Loss: FL(p_t) = -alpha_t * (1 - p_t)^gamma * log(p_t)
    Downweights easy negatives, focuses training on hard examples.
    """
    def __init__(self, gamma: float = 2.0, alpha: float = 0.25):
        super().__init__()
        self.gamma = gamma
        self.alpha = alpha

    def forward(self, logits: torch.Tensor, targets: torch.Tensor) -> torch.Tensor:
        ce_loss = F.cross_entropy(logits, targets, reduction='none')
        pt = torch.exp(-ce_loss)
        alpha_t = torch.where(targets == 1,
                              torch.full_like(ce_loss, self.alpha),
                              torch.full_like(ce_loss, 1 - self.alpha))
        focal = alpha_t * (1 - pt) ** self.gamma * ce_loss
        return focal.mean()


# ─── Metrics ─────────────────────────────────────────────────────────────────

def compute_metrics(y_true: list[int], y_pred: list[int], y_prob: list[float]) -> dict:
    if HAS_SKLEARN:
        return {
            "f1":        f1_score(y_true, y_pred, zero_division=0),
            "precision": precision_score(y_true, y_pred, zero_division=0),
            "recall":    recall_score(y_true, y_pred, zero_division=0),
            "auc":       roc_auc_score(y_true, y_prob) if len(set(y_true)) > 1 else 0.0,
            "accuracy":  sum(a == b for a, b in zip(y_true, y_pred)) / max(len(y_true), 1),
        }
    else:
        correct = sum(a == b for a, b in zip(y_true, y_pred))
        return {"accuracy": correct / max(len(y_true), 1), "f1": 0.0}


# ─── Training loop ────────────────────────────────────────────────────────────

def train_epoch(model, loader, optimizer, criterion, scheduler, device, scaler=None):
    model.train()
    total_loss = 0.0
    for tokens, labels in loader:
        tokens = tokens.to(device)
        labels = labels.to(device)
        optimizer.zero_grad()

        if scaler is not None:
            with torch.autocast(device_type=device.type):
                logits = model(tokens)
                loss = criterion(logits, labels)
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            scaler.step(optimizer)
            scaler.update()
        else:
            logits = model(tokens)
            loss = criterion(logits, labels)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

        scheduler.step()
        total_loss += loss.item()

    return total_loss / max(len(loader), 1)


@torch.no_grad()
def evaluate(model, loader, criterion, device):
    model.eval()
    total_loss = 0.0
    all_true, all_pred, all_prob = [], [], []

    for tokens, labels in loader:
        tokens = tokens.to(device)
        labels = labels.to(device)
        logits = model(tokens)
        loss = criterion(logits, labels)
        total_loss += loss.item()

        probs = torch.softmax(logits, dim=-1)[:, 1]
        preds = logits.argmax(dim=-1)

        all_true.extend(labels.cpu().tolist())
        all_pred.extend(preds.cpu().tolist())
        all_prob.extend(probs.cpu().tolist())

    metrics = compute_metrics(all_true, all_pred, all_prob)
    metrics["loss"] = total_loss / max(len(loader), 1)
    return metrics


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train Secret Squirrel CNN")
    parser.add_argument("--tier", choices=["tiny", "large"], default="tiny",
                        help="Which model tier to train")
    parser.add_argument("--epochs", type=int, default=20,
                        help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=256,
                        help="Batch size")
    parser.add_argument("--lr", type=float, default=3e-3,
                        help="Peak learning rate")
    parser.add_argument("--max-seq-len", type=int, default=256,
                        help="Sequence length (must match model tier)")
    parser.add_argument("--workers", type=int, default=0,
                        help="DataLoader workers (0 = main process)")
    parser.add_argument("--patience", type=int, default=5,
                        help="Early stopping patience (epochs)")
    args = parser.parse_args()

    # Device
    if torch.cuda.is_available():
        device = torch.device("cuda")
        print(f"  Using GPU: {torch.cuda.get_device_name(0)}")
        use_amp = True
    elif hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        device = torch.device("mps")
        print("  Using Apple MPS")
        use_amp = False
    else:
        device = torch.device("cpu")
        print(f"  Using CPU ({torch.get_num_threads()} threads)")
        use_amp = False

    # Model
    if args.tier == "tiny":
        model = build_tiny(args.max_seq_len)
    else:
        model = build_large(args.max_seq_len)

    model = model.to(device)
    print(f"\n{'='*60}")
    print(f"  Tier: {args.tier.upper()}")
    print(f"  Parameters: {model.count_parameters():,}")
    print(f"  Epochs:     {args.epochs}")
    print(f"  Batch size: {args.batch_size}")
    print(f"  Peak LR:    {args.lr}")
    print(f"{'='*60}\n")

    # Data
    train_path = DATA_DIR / "train.jsonl"
    val_path   = DATA_DIR / "val.jsonl"
    test_path  = DATA_DIR / "test.jsonl"

    if not train_path.exists():
        print("ERROR: training data not found. Run dataset_builder.py first.")
        raise SystemExit(1)

    print("Loading datasets...")
    train_ds = CredentialDataset(train_path, args.max_seq_len)
    val_ds   = CredentialDataset(val_path,   args.max_seq_len)
    test_ds  = CredentialDataset(test_path,  args.max_seq_len)
    print(f"  Train: {len(train_ds):,}  Val: {len(val_ds):,}  Test: {len(test_ds):,}")

    loader_kwargs = dict(
        batch_size=args.batch_size,
        num_workers=args.workers,
        pin_memory=(device.type == "cuda"),
    )
    train_loader = DataLoader(train_ds, shuffle=True,  **loader_kwargs)
    val_loader   = DataLoader(val_ds,   shuffle=False, **loader_kwargs)
    test_loader  = DataLoader(test_ds,  shuffle=False, **loader_kwargs)

    # Optimiser + LR schedule
    optimizer = AdamW(model.parameters(), lr=args.lr, weight_decay=1e-4)
    scheduler = OneCycleLR(
        optimizer,
        max_lr=args.lr,
        steps_per_epoch=len(train_loader),
        epochs=args.epochs,
        pct_start=0.1,       # 10% warmup
        anneal_strategy="cos",
    )

    # Loss — Focal Loss to handle any class imbalance
    criterion = FocalLoss(gamma=2.0, alpha=0.25)

    # AMP scaler for CUDA
    scaler = torch.cuda.amp.GradScaler() if use_amp else None

    # Training loop with early stopping
    best_f1 = 0.0
    best_ckpt = CKPT_DIR / f"squirrel-{args.tier}-best.pt"
    patience_counter = 0
    history = []

    print(f"Starting training for {args.epochs} epochs...\n")
    for epoch in range(1, args.epochs + 1):
        t0 = time.time()
        train_loss = train_epoch(model, train_loader, optimizer, criterion, scheduler, device, scaler)
        val_metrics = evaluate(model, val_loader, criterion, device)
        elapsed = time.time() - t0

        val_f1  = val_metrics.get("f1", 0.0)
        val_acc = val_metrics.get("accuracy", 0.0)
        val_auc = val_metrics.get("auc", 0.0)

        # Current LR
        current_lr = scheduler.get_last_lr()[0]

        print(
            f"Epoch {epoch:3d}/{args.epochs}  "
            f"loss={train_loss:.4f}  "
            f"val_loss={val_metrics['loss']:.4f}  "
            f"val_f1={val_f1:.4f}  "
            f"val_acc={val_acc:.4f}  "
            f"val_auc={val_auc:.4f}  "
            f"lr={current_lr:.2e}  "
            f"time={elapsed:.1f}s"
        )

        history.append({
            "epoch": epoch,
            "train_loss": train_loss,
            **{f"val_{k}": v for k, v in val_metrics.items()},
            "lr": current_lr,
        })

        # Save best checkpoint
        if val_f1 > best_f1:
            best_f1 = val_f1
            patience_counter = 0
            torch.save({
                "epoch": epoch,
                "model_state_dict": model.state_dict(),
                "optimizer_state_dict": optimizer.state_dict(),
                "val_f1": val_f1,
                "args": vars(args),
            }, best_ckpt)
            print(f"  ✓ New best F1={val_f1:.4f} — checkpoint saved")
        else:
            patience_counter += 1
            if patience_counter >= args.patience:
                print(f"\nEarly stopping at epoch {epoch} (no improvement for {args.patience} epochs)")
                break

    # Evaluate best model on test set
    print(f"\n{'='*60}")
    print("Loading best checkpoint for test evaluation...")
    ckpt = torch.load(best_ckpt, map_location=device)
    model.load_state_dict(ckpt["model_state_dict"])
    test_metrics = evaluate(model, test_loader, criterion, device)

    print(f"\nTest Results (best checkpoint from epoch {ckpt['epoch']}):")
    for k, v in test_metrics.items():
        print(f"  {k:12s}: {v:.4f}")

    # Save training history + results
    results_path = CKPT_DIR / f"squirrel-{args.tier}-results.json"
    with open(results_path, "w") as f:
        json.dump({
            "tier": args.tier,
            "best_val_f1": best_f1,
            "best_epoch": ckpt["epoch"],
            "test_metrics": test_metrics,
            "history": history,
            "args": vars(args),
        }, f, indent=2)
    print(f"\nResults saved to {results_path}")
    print(f"Best checkpoint:  {best_ckpt}")
    print(f"\nNext step: run  uv run python export_onnx.py --tier {args.tier}")


if __name__ == "__main__":
    main()
