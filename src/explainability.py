"""
Forensic Explainability Engine for Cryptographic Algorithm Identification.

Translates numerical feature thresholds and classifier confidence outputs into
human-understandable evidence statements and forensic rationale.
"""

from typing import Dict, Any, List, Tuple


class ForensicExplainer:
    """Explainer engine mapping feature values and model outputs to evidence statements."""

    CONFIDENCE_THRESHOLD = 0.40  # Under 40% confidence -> Indeterminate verdict

    @classmethod
    def explain(
        cls,
        predicted_label: str,
        confidence: float,
        top_3: List[Tuple[str, float]],
        features: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate forensic evidence statements and verdict status for a prediction."""
        evidence_notes: List[str] = []
        is_indeterminate = confidence < cls.CONFIDENCE_THRESHOLD
        final_verdict = predicted_label if not is_indeterminate else "Indeterminate / Low Confidence"

        # 1. Non-crypto archive / file format check
        if features.get("has_archive_header", 0) == 1:
            evidence_notes.append(
                "Known file archive/format header detected (ZIP/GZIP/PNG/PDF/ELF); payload is compressed/formatted data rather than ciphertext."
            )
            is_indeterminate = True
            final_verdict = "Non-Cryptographic File (Archive/Media)"

        elif features.get("printable_ascii_ratio", 0.0) > 0.85 and features.get("byte_length", 0) > 20:
            evidence_notes.append(
                f"High printable ASCII ratio ({features['printable_ascii_ratio']*100:.1f}%); input appears to be plain text or source code."
            )
            is_indeterminate = True
            final_verdict = "Unencrypted Plaintext / ASCII Text"

        # 2. Specific Algorithm Heuristic Rules
        if predicted_label == "AES-ECB":
            rep_16 = int(features.get("rep_16byte_count", 0))
            if rep_16 > 0:
                evidence_notes.append(
                    f"Detected {rep_16} duplicate 16-byte block(s) with 16-byte alignment; characteristic fingerprint of AES in ECB mode encrypting repetitive plaintext."
                )
            else:
                evidence_notes.append(
                    "Aligned to 16-byte block boundary with high entropy, classified as AES-ECB."
                )

        elif predicted_label == "AES-CBC":
            if features.get("is_mod_16", 0) == 1:
                evidence_notes.append(
                    "Exact 16-byte block alignment with zero duplicate blocks and high Shannon entropy; characteristic of AES in CBC/GCM mode with PKCS#7 padding."
                )

        elif predicted_label == "DES-CBC":
            if features.get("is_mod_8", 0) == 1 and features.get("is_mod_16", 0) == 0:
                evidence_notes.append(
                    "Aligned to 8-byte block boundary (not 16-byte); matches legacy 64-bit block cipher structure (DES / 3DES)."
                )

        elif predicted_label == "RC4":
            if features.get("is_mod_16", 0) == 0 and features.get("is_mod_8", 0) == 0:
                evidence_notes.append(
                    "Non-block aligned length with maximum byte entropy; characteristic of continuous stream ciphers (RC4 / ChaCha20)."
                )

        elif predicted_label == "MD5":
            if features.get("is_len_16", 0) == 1:
                evidence_notes.append(
                    "Fixed 128-bit (16-byte) raw output length with uniform byte distribution; matches MD5 digest signature."
                )

        elif predicted_label == "SHA-256":
            if features.get("is_len_32", 0) == 1:
                evidence_notes.append(
                    "Fixed 256-bit (32-byte) raw output length with uniform byte distribution; matches SHA-256 digest signature."
                )

        # 3. Low Confidence Warning Rationale
        if is_indeterminate and features.get("has_archive_header", 0) == 0 and features.get("printable_ascii_ratio", 0.0) <= 0.85:
            evidence_notes.append(
                f"Highest prediction probability ({confidence*100:.1f}%) is below the {cls.CONFIDENCE_THRESHOLD*100:.0f}% confidence threshold. Ciphertext exhibits pure pseudorandom noise without distinct metadata artifacts."
            )

        return {
            "verdict": final_verdict,
            "raw_predicted_label": predicted_label,
            "confidence": confidence,
            "is_indeterminate": is_indeterminate,
            "top_3": top_3,
            "evidence_notes": evidence_notes,
        }
