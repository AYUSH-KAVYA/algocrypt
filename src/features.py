"""
Feature Extraction Module for Cryptographic Algorithm Identification.

Translates raw ciphertext bytes or hex strings into numerical feature vectors
capturing structural properties, block repetition artifacts, and statistical metrics.
"""

from collections import Counter
from typing import Dict, Union, Any
import numpy as np
import pandas as pd


def _to_bytes(data: Union[str, bytes]) -> bytes:
    """Convert hex string or raw bytes into a byte array."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        cleaned = data.strip()
        if cleaned.startswith("0x") or cleaned.startswith("0X"):
            cleaned = cleaned[2:]
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
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

    # Printable ASCII byte ratio
    if length > 0:
        printable_count = sum(1 for b in data_bytes if 32 <= b <= 126 or b in (9, 10, 13))
        features["printable_ascii_ratio"] = printable_count / length
    else:
        features["printable_ascii_ratio"] = 0.0

    return features
