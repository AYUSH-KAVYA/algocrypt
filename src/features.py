"""
Feature Extraction Module for Cryptographic Algorithm Identification.

Translates raw ciphertext bytes or hex strings into numerical feature vectors
capturing structural properties, block repetition artifacts, statistical metrics,
and non-cryptographic file signatures.
"""

from collections import Counter
import math
import re
from typing import Dict, Union, Any, Tuple, List
import numpy as np
import pandas as pd


# Known non-cryptographic / archive magic byte signatures
ARCHIVE_MAGIC_BYTES = [
    b"PK\x03\x04",        # ZIP archive
    b"PK\x05\x06",        # Empty ZIP
    b"\x1f\x8b",          # GZIP compressed
    b"\x89PNG\r\n\x1a\n", # PNG image
    b"%PDF-",             # PDF document
    b"\x7fELF",           # Linux ELF executable
    b"BZh",               # BZIP2
    b"\xfd7zXZ\x00",      # XZ archive
]


def _to_bytes(data: Union[str, bytes]) -> bytes:
    """Convert hex string, text, or raw bytes into a raw byte array."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        cleaned = data.strip()
        if cleaned.startswith("0x") or cleaned.startswith("0X"):
            cleaned = cleaned[2:]
        # Check if valid hex string (even length, hex digits only)
        if len(cleaned) % 2 == 0 and bool(re.match(r"^[0-9a-fA-F]+$", cleaned)):
            try:
                return bytes.fromhex(cleaned)
            except ValueError:
                pass
        return cleaned.encode("utf-8")
    raise TypeError(f"Expected str or bytes, got {type(data)}")


def extract_structural_features(data_bytes: bytes) -> Dict[str, Union[int, float]]:
    """Extract length, modulo alignment, and hash length indicator features."""
    length = len(data_bytes)
    return {
        "byte_length": length,
        "is_len_16": int(length == 16),
        "is_len_32": int(length == 32),
        "is_len_64": int(length == 64),
        "is_mod_8": int(length > 0 and length % 8 == 0),
        "is_mod_16": int(length > 0 and length % 16 == 0),
    }


def extract_pattern_features(data_bytes: bytes) -> Dict[str, Union[int, float]]:
    """Extract block repetition counters, ECB mode fingerprints, and magic headers."""
    length = len(data_bytes)
    features: Dict[str, Union[int, float]] = {}

    # 8-byte block repetition
    if length >= 8:
        blocks_8 = [data_bytes[i:i+8] for i in range(0, length - length % 8, 8)]
        counts_8 = Counter(blocks_8)
        num_dup_8 = sum(count - 1 for count in counts_8.values() if count > 1)
        max_freq_8 = max(counts_8.values()) if counts_8 else 0
        features["rep_8byte_count"] = num_dup_8
        features["rep_8byte_max_freq"] = max_freq_8
        features["rep_8byte_ratio"] = num_dup_8 / len(blocks_8) if blocks_8 else 0.0
    else:
        features["rep_8byte_count"] = 0
        features["rep_8byte_max_freq"] = 0
        features["rep_8byte_ratio"] = 0.0

    # 16-byte block repetition (ECB Catcher)
    if length >= 16:
        blocks_16 = [data_bytes[i:i+16] for i in range(0, length - length % 16, 16)]
        counts_16 = Counter(blocks_16)
        num_dup_16 = sum(count - 1 for count in counts_16.values() if count > 1)
        max_freq_16 = max(counts_16.values()) if counts_16 else 0
        features["rep_16byte_count"] = num_dup_16
        features["rep_16byte_max_freq"] = max_freq_16
        features["rep_16byte_ratio"] = num_dup_16 / len(blocks_16) if blocks_16 else 0.0
    else:
        features["rep_16byte_count"] = 0
        features["rep_16byte_max_freq"] = 0
        features["rep_16byte_ratio"] = 0.0

    # OpenSSL magic header check: "Salted__" (b"Salted__")
    features["has_openssl_header"] = int(data_bytes.startswith(b"Salted__"))

    # Non-crypto archive / format magic header check
    has_archive = any(data_bytes.startswith(hdr) for hdr in ARCHIVE_MAGIC_BYTES)
    features["has_archive_header"] = int(has_archive)

    # Printable ASCII byte ratio
    if length > 0:
        printable_count = sum(1 for b in data_bytes if 32 <= b <= 126 or b in (9, 10, 13))
        features["printable_ascii_ratio"] = printable_count / length
    else:
        features["printable_ascii_ratio"] = 0.0

    return features


def extract_statistical_features(data_bytes: bytes) -> Dict[str, float]:
    """Extract Shannon entropy, byte distribution variance, Chi-Square stat, and serial correlation."""
    length = len(data_bytes)
    if length == 0:
        return {
            "shannon_entropy": 0.0,
            "byte_mean": 0.0,
            "byte_std": 0.0,
            "byte_var": 0.0,
            "chi_square_stat": 0.0,
            "serial_correlation": 0.0,
        }

    counts = Counter(data_bytes)
    
    # 1. Shannon Entropy (max 8.0)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    # 2. Byte value mean, std, variance
    arr = np.frombuffer(data_bytes, dtype=np.uint8)
    byte_mean = float(np.mean(arr))
    byte_std = float(np.std(arr))
    byte_var = float(np.var(arr))

    # 3. Chi-Square goodness-of-fit statistic against uniform distribution
    expected = length / 256.0
    chi_square = sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))

    # 4. Serial correlation coefficient (adjacent byte autocorrelation)
    if length > 1:
        x = arr[:-1].astype(np.float64)
        y = arr[1:].astype(np.float64)
        mean_x, mean_y = np.mean(x), np.mean(y)
        num = np.sum((x - mean_x) * (y - mean_y))
        den = np.sqrt(np.sum((x - mean_x) ** 2) * np.sum((y - mean_y) ** 2))
        serial_corr = float(num / den) if den > 0 else 0.0
    else:
        serial_corr = 0.0

    return {
        "shannon_entropy": float(entropy),
        "byte_mean": byte_mean,
        "byte_std": byte_std,
        "byte_var": byte_var,
        "chi_square_stat": float(chi_square),
        "serial_correlation": serial_corr,
    }


def extract_features(data: Union[str, bytes]) -> Dict[str, Union[int, float]]:
    """Extract complete numerical feature dictionary from input bytes or hex string."""
    data_bytes = _to_bytes(data)
    features = {}
    features.update(extract_structural_features(data_bytes))
    features.update(extract_pattern_features(data_bytes))
    features.update(extract_statistical_features(data_bytes))
    return features


def extract_features_dataframe(
    df: pd.DataFrame, hex_col: str = "ciphertext_hex", target_col: str = "label"
) -> Tuple[pd.DataFrame, pd.Series]:
    """Transform a dataset DataFrame into a numerical feature matrix X and target labels y."""
    feature_rows = []
    for hex_val in df[hex_col]:
        feature_rows.append(extract_features(hex_val))

    X = pd.DataFrame(feature_rows)
    y = df[target_col] if target_col in df.columns else pd.Series([], dtype=str)
    return X, y
