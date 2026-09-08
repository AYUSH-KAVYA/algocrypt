"""
Synthetic Cryptographic Dataset Generation Pipeline.
"""

import random
from typing import Dict, Any

from Crypto.Cipher import AES, DES, ARC4
from Crypto.Hash import MD5, SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Target Algorithm Configuration
TARGET_ALGORITHMS = {
    "AES-ECB": {"category": "block_16", "block_size": 16},
    "AES-CBC": {"category": "block_16", "block_size": 16},
    "DES-CBC": {"category": "block_8", "block_size": 8},
    "RC4": {"category": "stream", "block_size": 1},
    "MD5": {"category": "hash", "block_size": 1},
    "SHA-256": {"category": "hash", "block_size": 1},
}

PLAINTEXT_TYPES = ["repeated", "structured", "short", "natural_text", "random"]


class PlaintextGenerator:
    """Generates diverse plaintext payloads to expose implementation/metadata artifacts."""

    STRUCTURED_TEMPLATES = [
        '{"user_id": 10042, "status": "active", "roles": ["admin", "developer"], "session": "token_abc_1234567890"}',
        '<html><head><title>Test Page</title></head><body><h1>Welcome</h1><p>Standard boilerplate payload.</p></body></html>',
        'POST /api/v1/resource HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n{"data":"test"}',
        '<response><status>200</status><message>Operation completed successfully</message><id>987654321</id></response>',
        'LOG [2026-09-08 23:45:00] INFO com.example.service.AuthEngine: User authentication succeeded for session_id=89234',
    ]

    NATURAL_TEXT_SAMPLES = [
        "Cryptography is the practice and study of techniques for secure communication in the presence of adversarial third parties.",
        "The quick brown fox jumps over the lazy dog. Pack my box with five dozen liquor jugs. How vexingly quick daft zebras jump!",
        "def compute_hash(data: bytes) -> str:\n    import hashlib\n    return hashlib.sha256(data).hexdigest()\n",
        "Artificial intelligence and machine learning models can identify subtle structural patterns in encrypted data streams.",
        "Security is a process, not a product. Implementation details matter far more than theoretical cipher security alone.",
    ]

    @classmethod
    def generate(cls, ptype: str, target_len: int = 128) -> bytes:
        """Generate bytes for the requested plaintext type."""
        if ptype == "repeated":
            pattern_choice = random.choice([1, 2, 3, 4])
            if pattern_choice == 1:
                return b"\x00" * target_len
            elif pattern_choice == 2:
                return b"A" * target_len
            elif pattern_choice == 3:
                chunk = b"ABCDEF1234567890"
                return (chunk * (target_len // len(chunk) + 1))[:target_len]
            else:
                chunk = b"DEADBEEF"
                return (chunk * (target_len // len(chunk) + 1))[:target_len]

        elif ptype == "structured":
            base = random.choice(cls.STRUCTURED_TEMPLATES).encode("utf-8")
            if len(base) < target_len:
                base = base * (target_len // len(base) + 1)
            return base[:target_len]

        elif ptype == "short":
            short_len = random.randint(1, 15)
            return get_random_bytes(short_len)

        elif ptype == "natural_text":
            base = random.choice(cls.NATURAL_TEXT_SAMPLES).encode("utf-8")
            if len(base) < target_len:
                base = base * (target_len // len(base) + 1)
            return base[:target_len]

        elif ptype == "random":
            return get_random_bytes(target_len)

        else:
            raise ValueError(f"Unknown plaintext type: {ptype}")


class CryptoEngine:
    """Wrapper around PyCryptodome primitives with random key/IV generation."""

    @staticmethod
    def encrypt_sample(algo: str, plaintext: bytes) -> bytes:
        """Encrypt or hash the given plaintext using the target algorithm."""
        if algo == "AES-ECB":
            key = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_ECB)
            padded_pt = pad(plaintext, AES.block_size, style="pkcs7")
            return cipher.encrypt(padded_pt)

        elif algo == "AES-CBC":
            key = get_random_bytes(16)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            padded_pt = pad(plaintext, AES.block_size, style="pkcs7")
            return cipher.encrypt(padded_pt)

        elif algo == "DES-CBC":
            key = get_random_bytes(8)
            iv = get_random_bytes(8)
            cipher = DES.new(key, DES.MODE_CBC, iv=iv)
            padded_pt = pad(plaintext, DES.block_size, style="pkcs7")
            return cipher.encrypt(padded_pt)

        elif algo == "RC4":
            key = get_random_bytes(16)
            cipher = ARC4.new(key)
            return cipher.encrypt(plaintext)

        elif algo == "MD5":
            hasher = MD5.new()
            hasher.update(plaintext)
            return hasher.digest()

        elif algo == "SHA-256":
            hasher = SHA256.new()
            hasher.update(plaintext)
            return hasher.digest()

        else:
            raise ValueError(f"Unsupported algorithm: {algo}")
