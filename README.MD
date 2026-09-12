# AlgoCrypt: AI/ML Cryptographic Algorithm & Hash Identifier CLI

An AI/ML-driven forensic CLI application that analyzes unknown datasets or ciphertext files, extracts statistical, structural, and implementation-level metadata artifacts, and predicts the probable cryptographic algorithm or hash function used.

---

## 🔒 Cryptographic Nuance & Forensic Scope

**Why ML for Cryptography?**
Well-implemented modern ciphers (such as AES in CBC/GCM mode or ChaCha20) with random IVs produce pseudo-random ciphertexts with maximum byte entropy (~8.0 bits/byte). Mathematically recovering keys or ciphers purely from high-entropy ciphertext bytes without metadata is intractable.

**Where AlgoCrypt Excels (Implementation Artifacts & Fingerprints)**:
Rather than attempting impossible cryptanalysis on pure noise, **AlgoCrypt detects implementation-level weaknesses and structural signatures**:
- **ECB Mode Leakage**: Detects duplicate 16-byte (AES) or 8-byte (DES/3DES) blocks caused by Electronic Codebook mode encrypting repetitive plaintexts.
- **Fixed-Length Hash Signatures**: Recognizes exact digest output lengths (128-bit MD5, 256-bit SHA-256, 512-bit SHA-512).
- **Block Alignment & PKCS#7 Padding**: Distinguishes 16-byte block ciphers (AES) vs 8-byte block ciphers (DES) vs continuous stream ciphers (RC4) and hashes.
- **Format Magic Headers**: Scans for OpenSSL headers (`Salted__`) and non-cryptographic compressed format signatures (`ZIP`, `PNG`, `PDF`, `GZIP`, `ELF`) to eliminate false positives.
- **Statistical Byte Metrics**: Shannon entropy, Chi-Square goodness-of-fit to uniform distribution, byte variance, and serial autocorrelation.

---

## 🌟 Key Features

- 🎯 **Supported Algorithms (v1)**: `AES-ECB`, `AES-CBC`, `DES-CBC`, `RC4`, `MD5`, `SHA-256`.
- 🔍 **Forensic Explainability Engine (`--explain`)**: Translates numerical features into plain-language evidence statements (e.g. *"Detected 14 duplicate 16-byte blocks with 16-byte alignment; characteristic fingerprint of AES in ECB mode"*).
- 🛡️ **Non-Crypto Format Detector**: Identifies compressed archives (ZIP/PNG/PDF/GZIP) to prevent false-positive cipher classifications.
- ⚖️ **Confidence Thresholding (<40%)**: Refuses to force a random guess under high ambiguity, setting the verdict to **"Indeterminate / Low Confidence"**.
- ⚡ **Memory-Safe File Ingestion**: Caps byte stream reading at 10MB chunked, surviving massive 1GB+ files without crashing RAM.
- 🚨 **Fail-Fast Guards**: Cleanly handles 0-byte files and issues variance warnings for small files (<16 bytes).

---

## 📁 Repository Structure

```text
algocrypt/
├── demo_files/                 # Curated benchmark files for live demos & testing
│   ├── aes_ecb_pattern.bin     # AES-ECB ciphertext with 16-byte block repetition
│   ├── sha256_hash.bin         # 32-byte SHA-256 digest
│   ├── rc4_stream.bin          # RC4 stream cipher output
│   ├── archive_sample.zip      # ZIP archive (magic byte test)
│   ├── plain_text.txt          # Unencrypted ASCII text
│   └── empty_file.bin          # 0-byte guard sample
├── src/                        # Core source code
│   ├── dataset_gen.py          # Synthetic dataset generator with 5 plaintext types
│   ├── features.py             # Structural, pattern, & statistical feature extractor
│   ├── model.py                # RandomForest classifier & joblib persistence
│   ├── explainability.py       # Heuristic rule-based evidence translator
│   └── cli.py                  # Click CLI wrapper and dual-tier display
├── tests/                      # Automated pytest suite
│   ├── golden_samples/         # Test benchmark files
│   ├── test_dataset_gen.py     # Dataset pipeline unit tests
│   ├── test_features.py        # Feature extraction unit tests
│   ├── test_model.py           # Model training & serialization unit tests
│   └── test_explainability.py  # Forensic engine unit tests
├── data/                       # Dataset storage (data/dataset.csv)
├── models/                     # Trained model artifacts (models/model.joblib)
├── requirements.txt            # Python dependencies
└── setup.py                    # Package installer for global `algocrypt` command
```

---

## 🚀 Installation & Quickstart

```bash
# 1. Clone the repository
git clone https://github.com/AYUSH-KAVYA/algocrypt.git
cd algocrypt

# 2. Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies and the CLI globally in editable mode
pip install -e .
```

---

## 💻 CLI Usage

### 1. Analyze an Unknown File (Minimal Summary View)
```bash
algocrypt analyze --file demo_files/aes_ecb_pattern.bin
```

### 2. Analyze a File with Full Forensic Rationale (`--explain` / `-e`)
```bash
algocrypt analyze --file demo_files/aes_ecb_pattern.bin --explain
```

**Terminal Output Example**:
```text
=================================================================
               FORENSIC IDENTIFICATION REPORT               
=================================================================
 Target File     : demo_files/aes_ecb_pattern.bin
 File Size       : 272 bytes (2176 bits)
 Final Verdict   : AES-ECB
 Confidence Score: 96.00%
-----------------------------------------------------------------
 Top-3 Candidate Probabilities:
  1. AES-ECB    [████████████████████████████  ]  96.00%
  2. AES-CBC    [                              ]   2.00%
  3. DES-CBC    [                              ]   2.00%
-----------------------------------------------------------------
 Forensic Artifact Evidence:
  • Detected 14 duplicate 16-byte block(s) with 16-byte alignment; characteristic fingerprint of AES in ECB mode encrypting repetitive plaintext.
-----------------------------------------------------------------
 Key Feature Vector:
  • Shannon Entropy    : 5.1316 / 8.0000
  • Block Alignment    : 16-byte=True, 8-byte=True
  • 16-Byte Duplicates : 14 duplicate blocks (ratio: 0.82)
  • OpenSSL Header     : None
  • Format Magic Header: None
=================================================================
```

### 3. Generate Synthetic Dataset
```bash
algocrypt generate-dataset --num-samples 1200 --output data/dataset.csv --validate
```

### 4. Train & Save Classifier Model
```bash
algocrypt train --dataset data/dataset.csv --output models/model.joblib
```

### 5. Extract Feature Matrix
```bash
algocrypt extract-features --input data/dataset.csv --output data/features.csv
```

---

## 🧪 Automated Testing

Run the full automated test suite (15 unit tests covering dataset generation, feature extraction, model persistence, and explainability):

```bash
pytest tests/
```

---

## 📜 License

Distributed under the MIT License. Built for Problem 106 AI/ML Cryptographic Research.