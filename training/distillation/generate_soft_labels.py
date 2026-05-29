import argparse
import json
import os
import torch
from pathlib import Path
from tqdm import tqdm
from transformers import AutoTokenizer, AutoModelForSequenceClassification

def load_data(data_path: str):
    """Load existing dataset JSON."""
    with open(data_path, "r", encoding="utf-8") as f:
        return json.load(f)

def generate_soft_labels(data, model, tokenizer, device, batch_size=32):
    """Generate soft labels (logits/probabilities) for the dataset."""
    model.eval()
    results = []
    
    # Process in batches
    for i in tqdm(range(0, len(data), batch_size), desc="Generating soft labels"):
        batch = data[i:i + batch_size]
        texts = [item["text"] for item in batch]
        
        # Tokenize
        inputs = tokenizer(texts, padding=True, truncation=True, max_length=512, return_tensors="pt")
        inputs = {k: v.to(device) for k, v in inputs.items()}
        
        with torch.no_grad():
            outputs = model(**inputs)
            # Use softmax to get probabilities as soft labels
            probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
            
        for j, item in enumerate(batch):
            # Save original item and add soft labels
            new_item = item.copy()
            new_item["soft_label"] = probs[j].cpu().tolist()
            results.append(new_item)
            
    return results

def main():
    parser = argparse.ArgumentParser(description="Generate soft labels using CodeBERT")
    parser.add_argument("--data", type=str, default="../data/dataset.json", help="Path to input dataset")
    parser.add_argument("--output", type=str, default="../data/dataset_soft_labels.json", help="Path to save output")
    parser.add_argument("--model", type=str, default="microsoft/codebert-base", help="HuggingFace model name")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size for inference")
    args = parser.parse_args()
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Using device: {device}")
    
    # Check if input exists
    if not os.path.exists(args.data):
        print(f"Error: Dataset not found at {args.data}")
        # Create a dummy one for testing if not found
        os.makedirs(os.path.dirname(args.data), exist_ok=True)
        print("Creating dummy dataset for testing...")
        dummy_data = [
            {"text": "password = 'hunter2'", "label": 1},
            {"text": "let i = 0;", "label": 0}
        ]
        with open(args.data, "w") as f:
            json.dump(dummy_data, f)
            
    print(f"Loading tokenizer and model from {args.model}...")
    tokenizer = AutoTokenizer.from_pretrained(args.model)
    
    # Note: If using the base codebert, it doesn't have a classification head trained for secrets.
    # In a real scenario, this would be a fine-tuned CodeBERT model.
    try:
        model = AutoModelForSequenceClassification.from_pretrained(args.model)
    except Exception as e:
        print(f"Fallback to dummy sequence classification due to: {e}")
        # Initialize randomly if specific weights not found for sequence classification
        from transformers import AutoConfig
        config = AutoConfig.from_pretrained(args.model)
        config.num_labels = 2
        model = AutoModelForSequenceClassification.from_config(config)
        
    model.to(device)
    
    print(f"Loading data from {args.data}...")
    data = load_data(args.data)
    
    print(f"Generating soft labels for {len(data)} samples...")
    distilled_data = generate_soft_labels(data, model, tokenizer, device, args.batch_size)
    
    print(f"Saving distilled dataset to {args.output}...")
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(distilled_data, f, indent=2)
        
    print("Done!")

if __name__ == "__main__":
    main()
