#!/usr/bin/env python3
"""
models.py — CNN model definitions for Secret Squirrel classifier.

Both models use a character-level CNN with:
  - Embedding layer (vocab=100, matching the Rust tokenizer)
  - Multiple parallel convolution banks (TextCNN architecture)
  - Global max pooling
  - FC head with dropout → 2-class output

ModelTier     Params    Kernels             Filters  Dropout
──────────────────────────────────────────────────────────────
Tiny          ~500 K    [3, 4, 5]           128      0.5
Large         ~1 M      [3, 4, 5, 7, 9]    192      0.4
"""

import torch
import torch.nn as nn
import torch.nn.functional as F

# Must match cnn.rs constants
ALPHABET_SIZE = 100   # vocab size
PAD_IDX = 0           # padding index (used for masking)


class TextCNN(nn.Module):
    """
    Character-level TextCNN for credential classification.

    Input:  LongTensor [batch, seq_len]  — character indices 0..99
    Output: FloatTensor [batch, 2]       — logits for [benign, secret]
    """

    def __init__(
        self,
        vocab_size: int = ALPHABET_SIZE,
        embed_dim: int = 64,
        kernel_sizes: list[int] = (3, 4, 5),
        num_filters: int = 128,
        num_classes: int = 2,
        dropout: float = 0.5,
        max_seq_len: int = 256,
    ):
        super().__init__()
        self.embed_dim = embed_dim
        self.kernel_sizes = list(kernel_sizes)
        self.num_filters = num_filters
        self.max_seq_len = max_seq_len

        # Embedding — shared across all conv banks
        self.embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embed_dim,
            padding_idx=PAD_IDX,
        )

        # Parallel convolution banks (TextCNN-style)
        self.convs = nn.ModuleList([
            nn.Conv1d(
                in_channels=embed_dim,
                out_channels=num_filters,
                kernel_size=k,
            )
            for k in self.kernel_sizes
        ])

        # Batch norm after each conv bank for training stability
        self.bn = nn.ModuleList([
            nn.BatchNorm1d(num_filters)
            for _ in self.kernel_sizes
        ])

        self.dropout = nn.Dropout(dropout)

        # Classifier head
        total_filters = num_filters * len(self.kernel_sizes)
        self.fc1 = nn.Linear(total_filters, total_filters // 2)
        self.fc2 = nn.Linear(total_filters // 2, num_classes)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        x: LongTensor [B, L]
        returns: FloatTensor [B, 2]
        """
        # [B, L] → [B, L, E] → [B, E, L]  (Conv1d expects channels first)
        emb = self.embedding(x)           # [B, L, E]
        emb = emb.permute(0, 2, 1)       # [B, E, L]
        emb = self.dropout(emb)

        # Apply each conv bank + BN + ReLU + global max-pool
        pooled = []
        for conv, bn in zip(self.convs, self.bn):
            c = conv(emb)                  # [B, F, L-k+1]
            c = bn(c)
            c = F.relu(c)
            c = F.adaptive_max_pool1d(c, 1).squeeze(-1)  # [B, F]
            pooled.append(c)

        # Concatenate all pooled features
        h = torch.cat(pooled, dim=1)      # [B, F * n_kernels]
        h = self.dropout(h)

        # FC head
        h = F.relu(self.fc1(h))
        h = self.dropout(h)
        logits = self.fc2(h)              # [B, 2]

        return logits

    def count_parameters(self) -> int:
        return sum(p.numel() for p in self.parameters() if p.requires_grad)


def build_tiny(max_seq_len: int = 256) -> TextCNN:
    """~500K param model — target for GitHub Actions (2 MB ONNX)."""
    return TextCNN(
        vocab_size=ALPHABET_SIZE,
        embed_dim=64,
        kernel_sizes=[3, 4, 5],
        num_filters=128,
        num_classes=2,
        dropout=0.5,
        max_seq_len=max_seq_len,
    )


def build_large(max_seq_len: int = 256) -> TextCNN:
    """~1M param model — target for self-hosted runners (4 MB ONNX)."""
    return TextCNN(
        vocab_size=ALPHABET_SIZE,
        embed_dim=128,
        kernel_sizes=[3, 4, 5, 7, 9],
        num_filters=192,
        num_classes=2,
        dropout=0.4,
        max_seq_len=max_seq_len,
    )


if __name__ == "__main__":
    tiny = build_tiny()
    large = build_large()
    print(f"Tiny  params: {tiny.count_parameters():,}")
    print(f"Large params: {large.count_parameters():,}")

    # Quick forward pass test
    dummy = torch.zeros(4, 256, dtype=torch.long)
    out_t = tiny(dummy)
    out_l = large(dummy)
    print(f"Tiny  output shape: {out_t.shape}")
    print(f"Large output shape: {out_l.shape}")
    print("Model definitions OK ✓")
