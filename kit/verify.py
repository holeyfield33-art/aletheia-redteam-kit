"""Verify Ed25519 signatures on Aletheia receipts."""
from __future__ import annotations

import json
from pathlib import Path

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DEFAULT_PUBLIC_KEY_URL = "https://aletheia-core.com/.well-known/aletheia-receipt-key.pem"


def fetch_public_key(url: str = DEFAULT_PUBLIC_KEY_URL) -> bytes:
    """Fetch the Aletheia receipt-signing public key (Ed25519, PEM)."""
    resp = httpx.get(url, timeout=10.0)
    resp.raise_for_status()
    return resp.content


def verify_receipt(receipt: dict, public_key_pem: bytes) -> bool:
    """
    Verify a receipt's signature against the public key.
    Returns True if valid, False if invalid.
    Raises if the receipt is malformed.
    """
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be a dictionary")

    sig_hex = receipt.get("signature")
    if not sig_hex or not isinstance(sig_hex, str):
        return False
    if sig_hex == "UNSIGNED_DEV_MODE":
        return False

    try:
        signature = bytes.fromhex(sig_hex)
    except ValueError as exc:
        raise ValueError("receipt signature is not valid hex") from exc

    canonical_fields = [
        "request_id",
        "decision",
        "rule_id",
        "severity",
        "action",
        "policy_version",
        "semantic_engine",
    ]
    canonical = {k: receipt[k] for k in canonical_fields if k in receipt}
    message = json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()

    pubkey = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(pubkey, Ed25519PublicKey):
        raise ValueError("public key must be Ed25519")

    try:
        pubkey.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def verify_summary(summary_path: Path | str, public_key_url: str = DEFAULT_PUBLIC_KEY_URL) -> dict:
    """Verify every receipt in a summary.json. Return a verification report."""
    summary = json.loads(Path(summary_path).read_text())
    pubkey = fetch_public_key(public_key_url)

    verified = 0
    invalid = 0
    missing = 0
    for row in summary.get("results", []):
        receipt = row.get("receipt") or {}
        if not receipt or not receipt.get("signature"):
            missing += 1
            continue
        if verify_receipt(receipt, pubkey):
            verified += 1
        else:
            invalid += 1

    return {
        "total": len(summary.get("results", [])),
        "verified": verified,
        "invalid": invalid,
        "missing_signature": missing,
    }