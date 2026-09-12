"""
AlgoCrypt: AI/ML Cryptographic Algorithm Identification CLI Application.

Built with Click to analyze binary/text files, extract structural and statistical
artifacts, and predict probable cryptographic algorithms using a trained model.
"""

import os
import sys
from typing import Optional
import click
import pandas as pd

from src.dataset_gen import generate_dataset, validate_dataset
from src.features import extract_features, extract_features_dataframe
from src.model import train_model, save_model, load_model, predict_sample


DEFAULT_MODEL_PATH = "models/model.joblib"
DEFAULT_DATASET_PATH = "data/dataset.csv"
MAX_ANALYSIS_BYTES = 10 * 1024 * 1024  # 10 MB cap for memory safety on massive files


@click.group()
@click.version_option("1.0.0", prog_name="algocrypt")
def cli():
    """AlgoCrypt: AI/ML Cryptographic Algorithm & Hash Identifier CLI Tool."""
    pass


@cli.command()
@click.option("--file", "-f", "file_path", required=True, type=click.Path(exists=True), help="Path to input binary/text file to analyze.")
@click.option("--model", "-m", "model_path", default=DEFAULT_MODEL_PATH, help="Path to trained model file (.joblib).")
@click.option("--explain", "-e", "explain_mode", is_flag=True, help="Enable detailed forensic explainability view.")
def analyze(file_path: str, model_path: str, explain_mode: bool):
    """Analyze an unknown dataset/ciphertext file and predict the cryptographic algorithm."""
    # 1. Fail-Fast File Guard & Chunked Memory Protection
    try:
        file_size = os.path.getsize(file_path)
    except Exception as e:
        click.echo(click.style(f"[!] Error inspecting file '{file_path}': {e}", fg="red"))
        sys.exit(1)

    if file_size == 0:
        click.echo(click.style(f"[!] Error: File '{file_path}' is empty (0 bytes). Cannot perform classification.", fg="red", bold=True))
        sys.exit(1)

    if file_size < 16:
        click.echo(click.style(f"[!] Warning: File size ({file_size} bytes) is under 16 bytes. Statistical entropy calculations will have higher variance.", fg="yellow"))

    # Read file safely in chunks up to MAX_ANALYSIS_BYTES
    raw_buffer = bytearray()
    try:
        with open(file_path, "rb") as f:
            while len(raw_buffer) < MAX_ANALYSIS_BYTES:
                chunk = f.read(min(65536, MAX_ANALYSIS_BYTES - len(raw_buffer)))
                if not chunk:
                    break
                raw_buffer.extend(chunk)
    except Exception as e:
        click.echo(click.style(f"[!] Error reading file '{file_path}': {e}", fg="red"))
        sys.exit(1)

    raw_bytes = bytes(raw_buffer)
    analyzed_size = len(raw_bytes)

    # 2. Feature Extraction
    feature_dict = extract_features(raw_bytes)

    # 3. Load or Auto-Train Model
    if not os.path.exists(model_path):
        click.echo(click.style(f"[*] Model '{model_path}' not found. Training a fresh model...", fg="yellow"))
        if not os.path.exists(DEFAULT_DATASET_PATH):
            click.echo("[*] Generating synthetic dataset for training...")
            df_gen = generate_dataset(num_samples=1200, seed=42)
            os.makedirs(os.path.dirname(DEFAULT_DATASET_PATH), exist_ok=True)
            df_gen.to_csv(DEFAULT_DATASET_PATH, index=False)
        else:
            df_gen = pd.read_csv(DEFAULT_DATASET_PATH)

        X_train, y_train = extract_features_dataframe(df_gen)
        clf, metrics = train_model(X_train, y_train, seed=42)
        save_model(clf, model_path, feature_names=list(X_train.columns))
        click.echo(click.style(f"[+] Model trained and saved to {model_path}", fg="green"))

    clf, feature_names = load_model(model_path)

    # 4. Predict with Forensic Explainer
    top_label, top_conf, top_3, exp_dict = predict_sample((clf, feature_names), feature_dict)
    final_verdict = exp_dict["verdict"]

    # 5. Dual-Tier Terminal Display
    conf_pct = top_conf * 100
    color = "green" if conf_pct >= 80 and not exp_dict["is_indeterminate"] else "yellow" if conf_pct >= 40 else "red"

    if not explain_mode:
        # Minimal View
        click.echo(f"[+] File           : {file_path} ({file_size} bytes)")
        click.echo(f"[+] Top Prediction : " + click.style(f"{final_verdict}", fg=color, bold=True))
        click.echo(f"[+] Confidence     : " + click.style(f"{conf_pct:.2f}%", fg=color, bold=True))
        click.echo(click.style("    (Use --explain or -e for full forensic evidence report)", dim=True))
    else:
        # Full Forensic Explainable View
        click.echo("\n" + "=" * 65)
        click.echo(click.style("               FORENSIC IDENTIFICATION REPORT               ", fg="white", bg="blue", bold=True))
        click.echo("=" * 65)
        click.echo(f" Target File     : {file_path}")
        click.echo(f" File Size       : {file_size} bytes ({file_size * 8} bits)")
        if file_size > MAX_ANALYSIS_BYTES:
            click.echo(f" Analyzed Bytes  : {analyzed_size} bytes (capped at 10MB chunk for memory safety)")
        click.echo(f" Final Verdict   : " + click.style(f"{final_verdict}", fg=color, bold=True))
        click.echo(f" Confidence Score: " + click.style(f"{conf_pct:.2f}%", fg=color, bold=True))
        click.echo("-" * 65)

        click.echo(click.style(" Top-3 Candidate Probabilities:", bold=True))
        for idx, (algo, prob) in enumerate(top_3, 1):
            bar = "█" * int(prob * 30)
            click.echo(f"  {idx}. {algo:<10} [{bar:<30}] {prob * 100:6.2f}%")

        click.echo("-" * 65)
        click.echo(click.style(" Forensic Artifact Evidence:", bold=True))
        for note in exp_dict["evidence_notes"]:
            click.echo(f"  • {note}")

        click.echo("-" * 65)
        click.echo(click.style(" Key Feature Vector:", bold=True))
        click.echo(f"  • Shannon Entropy    : {feature_dict['shannon_entropy']:.4f} / 8.0000")
        click.echo(f"  • Block Alignment    : 16-byte={bool(feature_dict['is_mod_16'])}, 8-byte={bool(feature_dict['is_mod_8'])}")
        click.echo(f"  • 16-Byte Duplicates : {int(feature_dict['rep_16byte_count'])} duplicate blocks (ratio: {feature_dict['rep_16byte_ratio']:.2f})")
        click.echo(f"  • OpenSSL Header     : {'Detected (Salted__)' if feature_dict['has_openssl_header'] else 'None'}")
        click.echo(f"  • Format Magic Header: {'Detected' if feature_dict['has_archive_header'] else 'None'}")
        click.echo("=" * 65 + "\n")


@cli.command()
@click.option("--dataset", "-d", "dataset_path", default=DEFAULT_DATASET_PATH, help="Path to input CSV dataset.")
@click.option("--output", "-o", "model_path", default=DEFAULT_MODEL_PATH, help="Path to save trained model (.joblib).")
@click.option("--test-size", default=0.2, help="Validation split size (0.0 to 1.0).")
def train(dataset_path: str, model_path: str, test_size: float):
    """Train a Random Forest classifier on dataset and output evaluation metrics."""
    if not os.path.exists(dataset_path):
        click.echo(click.style(f"[!] Dataset file '{dataset_path}' not found. Run 'generate-dataset' first.", fg="red"))
        sys.exit(1)

    click.echo(f"[*] Reading dataset from {dataset_path}...")
    df = pd.read_csv(dataset_path) if dataset_path.endswith(".csv") else pd.read_parquet(dataset_path)

    click.echo("[*] Extracting feature vectors...")
    X, y = extract_features_dataframe(df)

    click.echo(f"[*] Training RandomForestClassifier on {len(X)} samples across {len(y.unique())} target classes...")
    clf, metrics = train_model(X, y, test_size=test_size, seed=42)

    click.echo("\n" + click.style("=== MODEL EVALUATION METRICS ===", fg="cyan", bold=True))
    click.echo(f" Accuracy Score: {metrics['accuracy'] * 100:.2f}%\n")
    click.echo("Classification Report:")
    click.echo(metrics["classification_report_text"])

    save_model(clf, model_path, feature_names=list(X.columns))
    click.echo(click.style(f"[+] Model saved to {model_path}", fg="green"))


@cli.command(name="generate-dataset")
@click.option("--num-samples", "-n", default=1200, help="Total samples to generate.")
@click.option("--output", "-o", default=DEFAULT_DATASET_PATH, help="Output dataset path.")
@click.option("--seed", default=42, help="Random seed.")
@click.option("--validate", is_flag=True, help="Run validation suite after generation.")
def generate(num_samples: int, output: str, seed: int, validate: bool):
    """Generate a synthetic cryptographic dataset."""
    click.echo(f"[*] Generating {num_samples} synthetic dataset samples...")
    df = generate_dataset(num_samples=num_samples, seed=seed)
    os.makedirs(os.path.dirname(output), exist_ok=True)
    
    if output.endswith(".parquet"):
        df.to_parquet(output, index=False)
    else:
        df.to_csv(output, index=False)
    click.echo(click.style(f"[+] Dataset exported to {output}", fg="green"))

    if validate:
        click.echo("[*] Running automated validation checks...")
        valid, issues = validate_dataset(df)
        if valid:
            click.echo(click.style("[✓] All dataset validation checks PASSED!", fg="green"))
        else:
            click.echo(click.style(f"[✗] Validation FAILED: {issues}", fg="red"))


@cli.command(name="extract-features")
@click.option("--input", "-i", default=DEFAULT_DATASET_PATH, help="Input dataset path.")
@click.option("--output", "-o", default="data/features.csv", help="Output feature matrix path.")
def extract(input: str, output: str):
    """Extract feature vectors from raw dataset into CSV/Parquet."""
    if not os.path.exists(input):
        click.echo(click.style(f"[!] Input file '{input}' not found.", fg="red"))
        sys.exit(1)

    click.echo(f"[*] Reading dataset from {input}...")
    df = pd.read_csv(input) if input.endswith(".csv") else pd.read_parquet(input)
    X, y = extract_features_dataframe(df)

    features_df = X.copy()
    if len(y) > 0:
        features_df["label"] = y.values

    os.makedirs(os.path.dirname(output), exist_ok=True)
    if output.endswith(".parquet"):
        features_df.to_parquet(output, index=False)
    else:
        features_df.to_csv(output, index=False)

    click.echo(click.style(f"[+] Extracted {X.shape[1]} features across {X.shape[0]} samples into {output}", fg="green"))


def main():
    cli()


if __name__ == "__main__":
    main()
