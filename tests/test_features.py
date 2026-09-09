"""
Unit tests for the feature extraction module.
"""

import pytest
import numpy as np
import pandas as pd
from src.features import (
    _to_bytes,
    extract_structural_features,
    extract_pattern_features,
    extract_statistical_features,
    extract_features,
    extract_features_dataframe,
)


def test_to_bytes_conversion():
    assert _to_bytes("4a8f9b") == b"\x4a\x8f\x9b"
    assert _to_bytes("0x4a8f9b") == b"\x4a\x8f\x9b"
    assert _to_bytes(b"\x01\x02\x03") == b"\x01\x02\x03"


def test_structural_features():
    feat_16 = extract_structural_features(b"A" * 16)
    assert feat_16["byte_length"] == 16
    assert feat_16["is_len_16"] == 1
    assert feat_16["is_len_32"] == 0
    assert feat_16["is_mod_8"] == 1
    assert feat_16["is_mod_16"] == 1

    feat_32 = extract_structural_features(b"B" * 32)
    assert feat_32["byte_length"] == 32
    assert feat_32["is_len_16"] == 0
    assert feat_32["is_len_32"] == 1
    assert feat_32["is_mod_16"] == 1


def test_pattern_features_ecb_repetition():
    # Repeated 16-byte block
    block_16 = b"0123456789abcdef"
    repeated_16 = block_16 * 4
    feats = extract_pattern_features(repeated_16)
    
    assert feats["rep_16byte_count"] == 3
    assert feats["rep_16byte_max_freq"] == 4
    assert feats["rep_16byte_ratio"] == 0.75

    # OpenSSL header check
    openssl_payload = b"Salted__1234567890abcdef"
    feats_hdr = extract_pattern_features(openssl_payload)
    assert feats_hdr["has_openssl_header"] == 1


def test_statistical_features_entropy():
    # Zero entropy for identical constant bytes
    constant_data = b"\x00" * 128
    stat_const = extract_statistical_features(constant_data)
    assert stat_const["shannon_entropy"] == 0.0
    assert stat_const["byte_var"] == 0.0

    # High entropy for pseudo-random bytes
    rng = np.random.default_rng(42)
    random_bytes = bytes(rng.integers(0, 256, size=1024, dtype=np.uint8))
    stat_rand = extract_statistical_features(random_bytes)
    assert 7.5 <= stat_rand["shannon_entropy"] <= 8.0


def test_extract_features_dataframe():
    sample_df = pd.DataFrame([
        {"sample_id": "1", "ciphertext_hex": "00" * 32, "label": "AES-ECB"},
        {"sample_id": "2", "ciphertext_hex": "4a8f9b" * 10, "label": "RC4"},
    ])
    X, y = extract_features_dataframe(sample_df)
    assert len(X) == 2
    assert len(y) == 2
    assert "shannon_entropy" in X.columns
    assert "rep_16byte_count" in X.columns
    assert y.iloc[0] == "AES-ECB"
