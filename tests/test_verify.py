from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from kit.verify import verify_receipt, verify_summary


def _build_signed_receipt() -> tuple[dict, bytes]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    receipt = {
        "request_id": "req-1",
        "decision": "DENIED",
        "rule_id": "R-9",
        "severity": "CRITICAL",
        "action": "fetch_data",
        "policy_version": "2026.05.01",
        "semantic_engine": "aletheia-v1",
    }
    message = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    receipt["signature"] = private_key.sign(message).hex()
    return receipt, public_pem


def test_verify_receipt_valid_signature() -> None:
    receipt, public_pem = _build_signed_receipt()
    assert verify_receipt(receipt, public_pem) is True


def test_verify_receipt_invalid_signature_returns_false() -> None:
    receipt, public_pem = _build_signed_receipt()
    receipt["signature"] = "00" * 64
    assert verify_receipt(receipt, public_pem) is False


def test_verify_receipt_malformed_signature_raises() -> None:
    receipt, public_pem = _build_signed_receipt()
    receipt["signature"] = "not-hex"
    with pytest.raises(ValueError, match="not valid hex"):
        verify_receipt(receipt, public_pem)


def test_verify_summary_counts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    good_receipt, public_pem = _build_signed_receipt()
    bad_receipt = dict(good_receipt)
    bad_receipt["signature"] = "11" * 64

    summary_path = tmp_path / "summary.json"
    summary_path.write_text(
        json.dumps(
            {
                "results": [
                    {"receipt": good_receipt},
                    {"receipt": bad_receipt},
                    {"receipt": {}},
                ]
            }
        )
    )

    monkeypatch.setattr("kit.verify.fetch_public_key", lambda url: public_pem)
    report = verify_summary(summary_path)
    assert report == {"total": 3, "verified": 1, "invalid": 1, "missing_signature": 1}