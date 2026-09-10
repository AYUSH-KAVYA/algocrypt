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


@click.group()
@click.version_option("1.0.0", prog_name="algocrypt")
def cli():
    """AlgoCrypt: AI/ML Cryptographic Algorithm & Hash Identifier CLI Tool."""
    pass


@cli.command()
@click.option("--file", "-f", "file_path", required=True, type=click.Path(exists=True), help="Path to input binary file to analyze.")
@click.option("--model", "-m", "model_path", default=DEFAULT_MODEL_PATH, help="Path to trained model file (.joblib).")
def analyze(file_path: str, model_path: str):
    """Analyze an unknown dataset/ciphertext file and predict the cryptographic algorithm."""
    click.echo(click.style(f"[*] Analyzing target file: {file_path}", fg="cyan", bold=True))

    # 1. Read binary content
    try:
        with open(file_path, "rb") as f:
            raw_bytes = f.read()
    except Exception as e:
        click.echo(click.style(f"[!] Failed to read file: {e}", fg="red"))
        sys.exit(1)

    file_size = len(raw_bytes)
    click.echo(f"[*] File Size: {file_size} bytes ({file_size * 8} bits)")

    if file_size == 0:
        click.echo(click.style("[!] Error: Input file is empty.", fg="red"))
        sys.exit(1)

    # 2. Extract features
    click.echo("[*] Extracting structural, pattern, and statistical features...")
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
        clf, _ = train_model(X_train, y_train, seed=42)
        save_model(clf, model_path)
        click.echo(click.style(f"[+] Model trained and saved to {model_path}", fg="green"))
    
    clf = load_model(model_path)

    # 4. Predict
    top_label, top_conf, top_3 = predict_sample(clf, feature_dict)

    # 5. Display Result
    click.echo("\n" + "=" * 60)
    click.echo(click.style("                  IDENTIFICATION RESULTS                  ", fg="white", bg="blue", bold=True))
    click.echo("=" * 60)
    
    conf_pct = top_conf * 100
    color = "green" if conf_pct >= 80 else "yellow" if conf_pct >= 50 else "red"
    click.echo(f" Top Prediction  : " + click.style(f"{top_label}", fg=color, bold=True))
    click.echo(f" Confidence Score: " + click.style(f"{conf_pct:.2f}%", fg=color, bold=True))
    click.echo("-" * 60)

    click.echo(click.style(" Top-3 Probable Algorithms:", bold=True))
    for idx, (algo, prob) in enumerate(top_3, 1):
        bar = "█" * int(prob * 30)
        click.echo(f"  {idx}. {algo:<10} [{bar:<30}] {prob * 100:6.2f}%")

    click.echo("-" * 60)
    click.echo(click.style(" Forensic Artifact Evidence:", bold=True))
    click.echo(f"  • Shannon Entropy    : {feature_dict['shannon_entropy']:.4f} / 8.0000")
    click.echo(f"  • Block Alignment    : 16-byte={bool(feature_dict['is_mod_16'])}, 8-byte={bool(feature_dict['is_mod_8'])}")
    click.echo(f"  • 16-Byte Duplicates : {int(feature_dict['rep_16byte_count'])} duplicate blocks")
    click.echo(f"  • OpenSSL Header     : {'Detected (Salted__)' if feature_dict['has_openssl_header'] else 'None'}")
    click.echo("=" * 60 + "\n")


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

    click.echo(f"[*] Training RandomForestClassifier on {len(X)} samples...")
    clf, metrics = train_model(X, y, test_size=test_size, seed=42)

    click.echo("\n" + click.style("=== MODEL EVALUATION METRICS ===", fg="cyan", bold=True))
    click.echo(f" Accuracy Score: {metrics['accuracy'] * 100:.2f}%\n")
    click.echo("Classification Report:")
    click.echo(metrics["classification_report_text"])

    save_model(clf, model_path)
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
