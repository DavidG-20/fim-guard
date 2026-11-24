"""Streaming SHA-256 hashing and constant-time HMAC-SHA256 signing."""

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

CHUNK_SIZE = 65_536  # 64 KiB


def hash_file_sha256(file_path: Path) -> str:
    """Compute the SHA-256 hex digest of a file using streaming reads."""
    hasher = hashlib.sha256()
    with file_path.open("rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            hasher.update(chunk)
    return hasher.hexdigest()


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Serialize a dictionary deterministically for HMAC computation."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(payload: dict[str, Any], secret_key: str) -> str:
    """Return the HMAC-SHA256 hex signature of a canonical JSON payload."""
    return hmac.new(
        secret_key.encode("utf-8"),
        _canonical_bytes(payload),
        hashlib.sha256,
    ).hexdigest()


def verify_signature(payload: dict[str, Any], secret_key: str, expected_sig: str) -> bool:
    """Verify an HMAC-SHA256 signature in constant time."""
    actual_sig = sign_payload(payload, secret_key)
    return hmac.compare_digest(actual_sig, expected_sig)
