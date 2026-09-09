"""
Feature Extraction Module for Cryptographic Algorithm Identification.

Translates raw ciphertext bytes or hex strings into numerical feature vectors
capturing structural properties, block repetition artifacts, and statistical metrics.
"""

from typing import Dict, Union, Any
import numpy as np
import pandas as pd


def _to_bytes(data: Union[str, bytes]) -> bytes:
    """Convert hex string or raw bytes into a byte array."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        # Handle optional hex prefix
        cleaned = data.strip()
        if cleaned.startswith("0x") or cleaned.startswith("0X"):
            cleaned = cleaned[2:]
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            # Fallback to UTF-8 encoding if string is not hex
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
