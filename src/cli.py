"""
Command Line Interface for Cryptographic Algorithm Identification Tool.
"""

import argparse
import os
import sys
import pandas as pd

from src.dataset_gen import generate_dataset, validate_dataset
from src.features import extract_features_dataframe


def main():
    parser = argparse.ArgumentParser(description="AlgoCrypt: AI/ML Cryptographic Algorithm Identification CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: generate-dataset
    gen_parser = subparsers.add_parser("generate-dataset", help="Generate synthetic cryptographic dataset")
    gen_parser.add_argument("--num-samples", type=int, default=1200, help="Total number of samples")
    gen_parser.add_argument("--output", type=str, default="data/dataset.csv", help="Output dataset path (.csv or .parquet)")
    gen_parser.add_argument("--seed", type=int, default=42, help="Random seed")
    gen_parser.add_argument("--validate", action="store_true", help="Run automated cryptographic validation")

    # Command: extract-features
    feat_parser = subparsers.add_parser("extract-features", help="Extract numerical features from raw dataset")
    feat_parser.add_argument("--input", type=str, default="data/dataset.csv", help="Input dataset path")
    feat_parser.add_argument("--output", type=str, default="data/features.csv", help="Output feature matrix path")

    args = parser.parse_args()

    if args.command == "generate-dataset":
        print(f"[*] Generating {args.num_samples} synthetic cryptographic dataset samples...")
        df = generate_dataset(num_samples=args.num_samples, seed=args.seed)
        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        
        if args.output.endswith(".parquet"):
            df.to_parquet(args.output, index=False)
        else:
            df.to_csv(args.output, index=False)
        print(f"[+] Dataset successfully exported to {args.output}")

        if args.validate:
            print("[*] Running automated validation checks...")
            valid, issues = validate_dataset(df)
            if valid:
                print("[✓] All dataset validation checks PASSED!")
            else:
                print("[✗] Validation FAILED with issues:", issues)

    elif args.command == "extract-features":
        if not os.path.exists(args.input):
            print(f"[!] Error: Input dataset file '{args.input}' not found. Run 'generate-dataset' first.")
            sys.exit(1)

        print(f"[*] Reading dataset from {args.input}...")
        df = pd.read_csv(args.input) if args.input.endswith(".csv") else pd.read_parquet(args.input)
        
        print("[*] Extracting numerical features from ciphertexts...")
        X, y = extract_features_dataframe(df)
        
        features_df = X.copy()
        if len(y) > 0:
            features_df["label"] = y.values

        os.makedirs(os.path.dirname(args.output), exist_ok=True)
        if args.output.endswith(".parquet"):
            features_df.to_parquet(args.output, index=False)
        else:
            features_df.to_csv(args.output, index=False)
            
        print(f"[+] Successfully extracted {X.shape[1]} features across {X.shape[0]} samples.")
        print(f"[+] Features exported to {args.output}")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
