"""
Unit tests for the forensic explainability engine.
"""

import pytest
from src.explainability import ForensicExplainer


def test_explain_aes_ecb():
    features = {
        "byte_length": 128,
        "is_mod_16": 1,
        "rep_16byte_count": 5,
        "shannon_entropy": 4.5,
        "has_archive_header": 0,
        "printable_ascii_ratio": 0.1,
    }
    top_3 = [("AES-ECB", 0.98), ("RC4", 0.01), ("AES-CBC", 0.01)]
    exp = ForensicExplainer.explain("AES-ECB", 0.98, top_3, features)

    assert exp["verdict"] == "AES-ECB"
    assert not exp["is_indeterminate"]
    assert any("duplicate 16-byte block" in note for note in exp["evidence_notes"])


def test_explain_low_confidence_threshold():
    features = {
        "byte_length": 100,
        "is_mod_16": 0,
        "rep_16byte_count": 0,
        "shannon_entropy": 7.95,
        "has_archive_header": 0,
        "printable_ascii_ratio": 0.05,
    }
    top_3 = [("AES-CBC", 0.35), ("RC4", 0.33), ("DES-CBC", 0.32)]
    exp = ForensicExplainer.explain("AES-CBC", 0.35, top_3, features)

    assert exp["is_indeterminate"]
    assert exp["verdict"] == "Indeterminate / Low Confidence"
    assert any("confidence threshold" in note for note in exp["evidence_notes"])


def test_explain_archive_header_detection():
    features = {
        "byte_length": 500,
        "is_mod_16": 0,
        "rep_16byte_count": 0,
        "shannon_entropy": 7.9,
        "has_archive_header": 1,
        "printable_ascii_ratio": 0.2,
    }
    top_3 = [("RC4", 0.60), ("AES-CBC", 0.30), ("DES-CBC", 0.10)]
    exp = ForensicExplainer.explain("RC4", 0.60, top_3, features)

    assert exp["is_indeterminate"]
    assert "Non-Cryptographic File" in exp["verdict"]
    assert any("archive/format header detected" in note for note in exp["evidence_notes"])
