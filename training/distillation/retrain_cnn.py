import argparse
import json
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
import numpy as np

# A simplified version of the CNN model for testing the distillation logic
class SecretCNN(nn.Module):
    def __init__(self, vocab_size=256, embed_dim=32, num_filters=64, filter_sizes=[3, 4, 5], num_classes=2):
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim)
        self.convs = nn.ModuleList([
            nn.Conv1d(embed_dim, num_filters, fs) for fs in filter_sizes
        ])
        self.dropout = nn.Dropout(0.5)
        self.fc = nn.Linear(len(filter_sizes) * num_filters, num_classes)
        
    def forward(self, x):
        # x is [batch_size, seq_len]
        x = self.embedding(x)  # [batch_size, seq_len, embed_dim]
        x = x.transpose(1, 2)  # [batch_size, embed_dim, seq_len]
        
        pooled = []
        for conv in self.convs:
            c = torch.relu(conv(x))
            p = torch.max_pool1d(c, c.size(2)).squeeze(2)
            pooled.append(p)
            
        x = torch.cat(pooled, dim=1)
        x = self.dropout(x)
        return self.fc(x)

class SoftLabelDataset(Dataset):
    def __init__(self, data_path, max_len=128):
        with open(data_path, "r") as f:
            self.data = json.load(f)
        self.max_len = max_len
        
    def __len__(self):
        return len(self.data)
        
    def __getitem__(self, idx):
        item = self.data[idx]
        text = item["text"]
        soft_label = item.get("soft_label", [1.0, 0.0] if item.get("label") == 0 else [0.0, 1.0])
        
        # Simple byte conversion
        bytes_data = text.encode('utf-8')[:self.max_len]
        indices = [b for b in bytes_data]
        if len(indices) < self.max_len:
            indices.extend([0] * (self.max_len - len(indices)))
            
        return torch.tensor(indices, dtype=torch.long), torch.tensor(soft_label, dtype=torch.float)

def train(model, dataloader, optimizer, criterion, device):
    model.train()
    total_loss = 0
    for inputs, targets in dataloader:
        inputs, targets = inputs.to(device), targets.to(device)
        
        optimizer.zero_grad()
        outputs = model(inputs)
        
        # Note: KL Div or MSE can be used for distillation. 
        # For simplicity with probabilities as targets, we use BCEWithLogitsLoss
        # Or MSE on softmax outputs
        probs = torch.softmax(outputs, dim=-1)
        loss = criterion(probs, targets)
        
        loss.backward()
        optimizer.step()
        
        total_loss += loss.item()
        
    return total_loss / len(dataloader)

def main():
    parser = argparse.ArgumentParser(description="Retrain CNN using distilled soft labels")
    parser.add_argument("--data", type=str, default="../data/dataset_soft_labels.json", help="Path to distilled dataset")
    parser.add_argument("--epochs", type=int, default=10, help="Number of training epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--output", type=str, default="../checkpoints/cnn_distilled.pt", help="Path to save model")
    args = parser.parse_args()
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    
    # Check if input exists
    import os
    if not os.path.exists(args.data):
        print(f"Error: Dataset not found at {args.data}. Run generate_soft_labels.py first.")
        return
        
    print(f"Loading data from {args.data}...")
    dataset = SoftLabelDataset(args.data)
    dataloader = DataLoader(dataset, batch_size=args.batch_size, shuffle=True)
    
    print("Initializing model...")
    model = SecretCNN().to(device)
    optimizer = optim.Adam(model.parameters(), lr=args.lr)
    
    # Knowledge Distillation typically uses KL Divergence or MSE
    criterion = nn.MSELoss()
    
    print("Starting training...")
    for epoch in range(args.epochs):
        loss = train(model, dataloader, optimizer, criterion, device)
        print(f"Epoch {epoch+1}/{args.epochs} - Loss: {loss:.4f}")
        
    print(f"Saving retrained model to {args.output}...")
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    torch.save(model.state_dict(), args.output)
    
    # Also export to ONNX for Secret Squirrel
    onnx_path = args.output.replace('.pt', '.onnx')
    print(f"Exporting to ONNX at {onnx_path}...")
    dummy_input = torch.zeros((1, 128), dtype=torch.long).to(device)
    torch.onnx.export(
        model, dummy_input, onnx_path,
        export_params=True,
        opset_version=14,
        do_constant_folding=True,
        input_names=['input'],
        output_names=['output'],
        dynamic_axes={'input': {0: 'batch_size', 1: 'seq_len'}, 'output': {0: 'batch_size'}}
    )
    print("Done!")

if __name__ == "__main__":
    main()
