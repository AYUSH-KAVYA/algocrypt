"""
Unit tests for synthetic dataset generator.
"""

import pytest
import pandas as pd
from src.dataset_gen import generate_dataset, validate_dataset, PlaintextGenerator, CryptoEngine


def test_plaintext_generator_types():
    pt_types = ["repeated", "structured", "short", "natural_text", "random"]
    for ptype in pt_types:
        data = PlaintextGenerator.generate(ptype, target_len=100)
        assert isinstance(data, bytes)
        assert len(data) > 0
        if ptype == "short":
            assert len(data) < 16


def test_crypto_engine_outputs():
    pt = b"Hello, World! Security artifact test payload 123456789."
    
    aes_ecb = CryptoEngine.encrypt_sample("AES-ECB", pt)
    assert len(aes_ecb) % 16 == 0
    
    aes_cbc = CryptoEngine.encrypt_sample("AES-CBC", pt)
    assert len(aes_cbc) % 16 == 0
    
    des_cbc = CryptoEngine.encrypt_sample("DES-CBC", pt)
    assert len(des_cbc) % 8 == 0
    
    rc4 = CryptoEngine.encrypt_sample("RC4", pt)
    assert len(rc4) == len(pt)
    
    md5 = CryptoEngine.encrypt_sample("MD5", pt)
    assert len(md5) == 16
    
    sha256 = CryptoEngine.encrypt_sample("SHA-256", pt)
    assert len(sha256) == 32


def test_generate_and_validate_dataset():
    df = generate_dataset(num_samples=120, seed=123)
    assert len(df) == 120
    assert set(df["label"].unique()) == {"AES-ECB", "AES-CBC", "DES-CBC", "RC4", "MD5", "SHA-256"}
    
    is_valid, issues = validate_dataset(df)
    assert is_valid, f"Dataset validation failed: {issues}"


def test_ecb_repeated_block_leakage():
    # Verify that repeated plaintexts encrypted with AES-ECB leak duplicate 16-byte blocks
    repeated_pt = b"\x00" * 64
    ct_ecb = CryptoEngine.encrypt_sample("AES-ECB", repeated_pt)
    ct_hex = ct_ecb.hex()
    blocks = [ct_hex[i:i+32] for i in range(0, len(ct_hex), 32)]
    # Should have duplicate blocks
    assert len(blocks) > len(set(blocks)), "AES-ECB failed to exhibit duplicate blocks on zero plaintext"

    # CBC mode with random IV should NOT exhibit duplicate blocks on the same repeated plaintext
    ct_cbc = CryptoEngine.encrypt_sample("AES-CBC", repeated_pt)
    ct_cbc_hex = ct_cbc.hex()
    cbc_blocks = [ct_cbc_hex[i:i+32] for i in range(0, len(ct_cbc_hex), 32)]
    assert len(cbc_blocks) == len(set(cbc_blocks)), "AES-CBC improperly produced duplicate blocks"
