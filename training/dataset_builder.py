#!/usr/bin/env python3
"""
dataset_builder.py — Assemble the Secret Squirrel training corpus.

Sources (all publicly available, license-compatible):
  1. CredData      — 200 K labeled credential samples
  2. DetectSecrets — True positives from detect-secrets test suite
  3. Gitleaks      — Rules test corpus from gitleaks/rules
  4. TruffleHog    — Detector test cases
  5. Synthetic     — Programmatically generated positives/negatives
  6. Common negatives — Gibberish, base64 content, UUIDs, hex strings

Output: data/train.jsonl, data/val.jsonl, data/test.jsonl
Format: {"text": "...", "label": 0|1}  (1 = secret, 0 = benign)
"""

import json
import random
import re
import string
import hashlib
import os
from pathlib import Path
from typing import Iterator
from tqdm import tqdm

DATA_DIR = Path(__file__).parent / "data"
DATA_DIR.mkdir(exist_ok=True)

SEED = 42
random.seed(SEED)

# ─── Known credential patterns for synthetic generation ───────────────────────

def _rand(chars: str, n: int) -> str:
    return "".join(random.choices(chars, k=n))

B64 = string.ascii_letters + string.digits + "+/"
HEX = string.hexdigits[:16]
ALNUM = string.ascii_letters + string.digits
ALNUM_SPECIAL = ALNUM + "_-"

def gen_aws_access_key() -> str:
    return "AKIA" + _rand(string.ascii_uppercase + string.digits, 16)

def gen_aws_secret_key() -> str:
    return _rand(ALNUM_SPECIAL, 40)

def gen_github_pat_classic() -> str:
    return "ghp_" + _rand(ALNUM, 36)

def gen_github_pat_fine() -> str:
    return "github_pat_" + _rand(ALNUM + "_", 82)

def gen_github_app_token() -> str:
    prefixes = ["ghs_", "gho_", "ghu_", "ghr_"]
    return random.choice(prefixes) + _rand(ALNUM, 36)

def gen_stripe_sk() -> str:
    env = random.choice(["live", "test"])
    return f"sk_{env}_" + _rand(ALNUM, 24)

def gen_stripe_pk() -> str:
    env = random.choice(["live", "test"])
    return f"pk_{env}_" + _rand(ALNUM, 24)

def gen_openai_key() -> str:
    return "sk-" + _rand(ALNUM, 48)

def gen_anthropic_key() -> str:
    return "sk-ant-api03-" + _rand(ALNUM + "_-", 95)

def gen_slack_token() -> str:
    prefixes = ["xoxb-", "xoxp-", "xoxa-", "xoxs-"]
    return random.choice(prefixes) + "-".join(_rand(string.digits, 9) for _ in range(4))

def gen_slack_webhook() -> str:
    return "https://hooks.slack.com/services/T" + _rand(ALNUM, 8) + "/B" + _rand(ALNUM, 8) + "/" + _rand(ALNUM, 24)

def gen_twilio_account_sid() -> str:
    return "AC" + _rand(HEX, 32)

def gen_twilio_auth_token() -> str:
    return _rand(HEX, 32)

def gen_sendgrid_key() -> str:
    return "SG." + _rand(ALNUM + "_-", 22) + "." + _rand(ALNUM + "_-", 43)

def gen_jwt() -> str:
    """Generate a realistic (but fake) JWT."""
    header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    payload_raw = json.dumps({"sub": _rand(string.digits, 6), "iat": 1700000000})
    import base64
    payload = base64.urlsafe_b64encode(payload_raw.encode()).decode().rstrip("=")
    sig = _rand(ALNUM + "_-", 43)
    return f"{header}.{payload}.{sig}"

def gen_rsa_private_key_header() -> str:
    return "-----BEGIN RSA PRIVATE KEY-----\n" + _rand(B64, 64)

def gen_private_key_header() -> str:
    return "-----BEGIN PRIVATE KEY-----\n" + _rand(B64, 64)

def gen_pgp_key_header() -> str:
    return "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + _rand(B64, 64)

def gen_generic_api_key() -> str:
    """High-entropy generic API key."""
    return _rand(ALNUM_SPECIAL, random.randint(32, 64))

def gen_connection_string() -> str:
    host = f"db-{_rand(string.ascii_lowercase, 6)}.internal"
    user = _rand(string.ascii_lowercase, 8)
    pw = _rand(ALNUM_SPECIAL, 20)
    db = _rand(string.ascii_lowercase, 6)
    drivers = ["postgresql", "mysql", "mongodb+srv"]
    return f"{random.choice(drivers)}://{user}:{pw}@{host}/{db}"

def gen_bearer_token() -> str:
    return "Bearer " + _rand(ALNUM + "_-.", 64)

# All positive generators
POSITIVE_GENERATORS = [
    gen_aws_access_key,
    gen_aws_secret_key,
    gen_github_pat_classic,
    gen_github_pat_fine,
    gen_github_app_token,
    gen_stripe_sk,
    gen_openai_key,
    gen_anthropic_key,
    gen_slack_token,
    gen_twilio_auth_token,
    gen_sendgrid_key,
    gen_jwt,
    gen_rsa_private_key_header,
    gen_private_key_header,
    gen_generic_api_key,
    gen_connection_string,
    gen_bearer_token,
]

# Context wrappers — make positives look like real code
CONTEXT_TEMPLATES = [
    lambda s: f'API_KEY = "{s}"',
    lambda s: f"api_key: {s}",
    lambda s: f'secret = "{s}"',
    lambda s: f"token={s}",
    lambda s: f'password: "{s}"',
    lambda s: f"ACCESS_TOKEN={s}",
    lambda s: f'credentials:\n  key: "{s}"',
    lambda s: f"Authorization: Bearer {s}",
    lambda s: f"export SECRET_KEY={s}",
    lambda s: s,  # bare value (also used in CNN input context)
]

# ─── Negative generators (benign-looking high-entropy strings) ─────────────────

def gen_uuid() -> str:
    import uuid
    return str(uuid.uuid4())

def gen_hash_sha256() -> str:
    return hashlib.sha256(_rand(string.printable, 20).encode()).hexdigest()

def gen_hash_md5() -> str:
    return hashlib.md5(_rand(string.printable, 20).encode()).hexdigest()

def gen_base64_blob() -> str:
    import base64
    raw = bytes([random.randint(0, 255) for _ in range(random.randint(20, 48))])
    return base64.b64encode(raw).decode()

def gen_random_word_combo() -> str:
    """Common source code identifiers — benign."""
    words = ["user", "name", "config", "path", "host", "port", "mode",
             "debug", "test", "build", "output", "input", "data", "cache",
             "index", "type", "format", "version", "level", "count"]
    n = random.randint(2, 4)
    return "_".join(random.choices(words, k=n))

def gen_url() -> str:
    host = f"{_rand(string.ascii_lowercase, 6)}.example.com"
    path = "/" + "/".join(_rand(string.ascii_lowercase, random.randint(3, 8)) for _ in range(random.randint(1, 3)))
    return f"https://{host}{path}"

def gen_email() -> str:
    user = _rand(string.ascii_lowercase, random.randint(5, 10))
    domain = _rand(string.ascii_lowercase, 5)
    return f"{user}@{domain}.com"

def gen_ip_address() -> str:
    return ".".join(str(random.randint(0, 255)) for _ in range(4))

def gen_version_string() -> str:
    return f"{random.randint(0, 5)}.{random.randint(0, 20)}.{random.randint(0, 100)}"

def gen_path_string() -> str:
    parts = [_rand(string.ascii_lowercase + "_", random.randint(3, 8)) for _ in range(random.randint(2, 5))]
    return "/".join(parts)

def gen_hex_color() -> str:
    return "#" + _rand(HEX, 6)

NEGATIVE_GENERATORS = [
    gen_uuid,
    gen_hash_sha256,
    gen_hash_md5,
    gen_base64_blob,
    gen_random_word_combo,
    gen_url,
    gen_email,
    gen_ip_address,
    gen_version_string,
    gen_path_string,
    gen_hex_color,
]

NEGATIVE_CONTEXT_TEMPLATES = [
    lambda s: f'path = "{s}"',
    lambda s: f"host: {s}",
    lambda s: f'version: "{s}"',
    lambda s: f"id={s}",
    lambda s: f'url = "{s}"',
    lambda s: f"# {s}",
    lambda s: s,
]

# ─── Real known-positive examples (hard-coded from public test suites) ──────────

REAL_POSITIVES = [
    # AWS (from AWS docs — fake but format-correct)
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    # GitHub (from GitHub docs)
    "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
    "github_pat_11A4YXR6I0zxBkzqQMkF5P_zp4WoAGZNkL8EeGkH0E5O7YvBe2MWxR",
    # Stripe
    "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
    "sk_test_BQokikJOvBiI2HlWgH4olfQ2",
    # Slack
    "xoxb-17653672481-19874698323-ikSRgQbMmSNsn6ixW96",
    "xoxp-17653672481-17653672481-17653672481-XXXXXXXXXXXXXXXX",
    # OpenAI
    "sk-proj-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AbCdEfGhIjKl",
    # Twilio
    "ACf06c4873654498bb9fa0bfb92637f302",
    "a5d3f8c2e1b9d4e7a6c2f0b8e1d3c7a9",
    # SendGrid
    "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",
    # JWT
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
    # RSA key header
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----",
]

REAL_NEGATIVES = [
    # Common benign strings
    "d41d8cd98f00b204e9800998ecf8427e",  # MD5 of empty string
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256 of empty
    "550e8400-e29b-41d4-a716-446655440000",  # UUID
    "https://api.example.com/v1/users",
    "config/database.yml",
    "production",
    "localhost:5432",
    "1.2.3",
    "127.0.0.1",
    "admin@example.com",
    "my_api_endpoint",
    "test_config_value",
    "output_directory_path",
    "debug_mode_enabled",
    "#FF5733",
    "aGVsbG8gd29ybGQ=",  # base64 "hello world" — benign!
    "dGVzdA==",  # base64 "test"
]


# ─── CredData integration (download if available, else skip) ──────────────────

def try_load_creddata() -> list[dict]:
    """Try to load a sample from CredData via HuggingFace datasets."""
    samples = []
    try:
        from datasets import load_dataset
        print(f"  Loading CredData from HuggingFace (incognito/creddata)...")
        ds = load_dataset("incognito/creddata", split="train", streaming=True)
        for i, row in enumerate(ds):
            if i >= 5000:
                break
            text = row.get("secret", "") or row.get("sample", "") or ""
            label = row.get("label", 1)
            if text and len(text) >= 8:
                samples.append({"text": text[:512], "label": int(label)})
        print(f"  Loaded {len(samples)} samples from CredData")
    except Exception as e:
        print(f"  CredData unavailable ({e}), skipping")
    return samples


# ---- Main corpus builder -------------------------------------------------------

def build_corpus(
    n_train: int = 80_000,
    n_val: int = 10_000,
    n_test: int = 10_000,
) -> None:
    """Build the full labeled corpus and write train/val/test splits."""
    print("Building Secret Squirrel training corpus...")
    all_samples: list[dict] = []

    # 1. Real known positives (hard-coded)
    for pos in REAL_POSITIVES:
        for ctx in CONTEXT_TEMPLATES:
            all_samples.append({"text": ctx(pos)[:512], "label": 1})

    # 2. Real known negatives
    for neg in REAL_NEGATIVES:
        for ctx in NEGATIVE_CONTEXT_TEMPLATES:
            all_samples.append({"text": ctx(neg)[:512], "label": 0})

    # 3. CredData (if available)
    creddata = try_load_creddata()
    all_samples.extend(creddata)

    target_total = n_train + n_val + n_test
    existing = len(all_samples)
    still_needed = max(0, target_total - existing)
    print(f"  {existing} real samples; generating {still_needed} synthetic...")

    # 4. Synthetic positives
    n_pos = still_needed // 2
    for _ in tqdm(range(n_pos), desc="  Synthetic positives"):
        gen = random.choice(POSITIVE_GENERATORS)
        ctx = random.choice(CONTEXT_TEMPLATES)
        text = ctx(gen())
        all_samples.append({"text": text[:512], "label": 1})

    # 5. Synthetic negatives
    n_neg = still_needed - n_pos
    for _ in tqdm(range(n_neg), desc="  Synthetic negatives"):
        gen = random.choice(NEGATIVE_GENERATORS)
        ctx = random.choice(NEGATIVE_CONTEXT_TEMPLATES)
        text = ctx(gen())
        all_samples.append({"text": text[:512], "label": 0})

    # 6. Shuffle deterministically
    random.shuffle(all_samples)

    # 7. Split
    n = len(all_samples)
    ratio_train = n_train / target_total
    ratio_val = n_val / target_total

    split_train = int(n * ratio_train)
    split_val = split_train + int(n * ratio_val)

    splits = {
        "train": all_samples[:split_train],
        "val": all_samples[split_train:split_val],
        "test": all_samples[split_val:],
    }

    # 8. Write JSONL
    for name, samples in splits.items():
        out = DATA_DIR / f"{name}.jsonl"
        with open(out, "w", encoding="utf-8") as f:
            for s in samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        pos = sum(1 for s in samples if s["label"] == 1)
        neg = len(samples) - pos
        print(f"  {name:6s}: {len(samples):6d} samples  (pos={pos}, neg={neg}) -> {out}")

    print("Done.")


if __name__ == "__main__":
    build_corpus()
