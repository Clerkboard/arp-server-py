"""ACP cryptographic operations: Ed25519 key management, signing, verification, multibase encoding."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Tuple

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

logger = logging.getLogger(__name__)

# Multicodec prefix for Ed25519 public keys (2 bytes: 0xed 0x01).
ED25519_MULTICODEC_PREFIX = bytes([0xED, 0x01])


def canonicalize(obj: Any) -> str:
    """Produce a JCS (RFC 8785) canonical JSON string.

    Uses sorted keys and compact separators with no ASCII escaping,
    which matches the JSON Canonicalization Scheme for the subset of
    values we handle (no special floats).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def multibase_encode(raw_bytes: bytes) -> str:
    """Encode raw bytes as a multibase base58btc string (z-prefix)."""
    return "z" + base58.b58encode(raw_bytes).decode("ascii")


def multibase_decode(multibase: str) -> bytes:
    """Decode a multibase base58btc string (z-prefix) to raw bytes."""
    if not multibase.startswith("z"):
        raise ValueError("Multibase string must start with 'z' (base58btc)")
    return base58.b58decode(multibase[1:])


def generate_keypair() -> Tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate a fresh Ed25519 key pair."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def private_key_to_hex(private_key: Ed25519PrivateKey) -> str:
    """Serialize an Ed25519 private key to a hex string of its raw 32 bytes."""
    raw = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return raw.hex()


def public_key_to_multibase(public_key: Ed25519PublicKey) -> str:
    """Serialize an Ed25519 public key to multibase base58btc with multicodec prefix."""
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return multibase_encode(ED25519_MULTICODEC_PREFIX + raw)


def private_key_from_hex(hex_str: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a hex string."""
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_str))


def public_key_from_multibase(multibase: str) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a multibase base58btc string.

    Handles both multicodec-prefixed (34 bytes) and raw (32 bytes) formats.
    """
    decoded = multibase_decode(multibase)
    if len(decoded) == 34 and decoded[:2] == ED25519_MULTICODEC_PREFIX:
        raw = decoded[2:]
    elif len(decoded) == 32:
        raw = decoded
    else:
        raise ValueError(
            f"Invalid Ed25519 public key: expected 34 bytes (multicodec-prefixed) "
            f"or 32 bytes (raw), got {len(decoded)}"
        )
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_message(message: dict, private_key: Ed25519PrivateKey) -> dict:
    """Sign an ACP message envelope.

    Takes a message dict WITHOUT a ``signature`` field, canonicalizes it,
    signs with the private key, and returns a new dict with the ``signature``
    field added.
    """
    msg_copy = {k: v for k, v in message.items() if k != "signature"}
    canonical = canonicalize(msg_copy)
    sig_bytes = private_key.sign(canonical.encode("utf-8"))
    signed = dict(message)
    signed["signature"] = multibase_encode(sig_bytes)
    return signed


def verify_signature(message: dict, public_key: Ed25519PublicKey) -> bool:
    """Verify the signature on an ACP message envelope.

    Returns True if valid, False otherwise.
    """
    sig_multibase = message.get("signature")
    if not sig_multibase:
        return False

    msg_copy = {k: v for k, v in message.items() if k != "signature"}
    canonical = canonicalize(msg_copy)

    try:
        sig_bytes = multibase_decode(sig_multibase)
        public_key.verify(sig_bytes, canonical.encode("utf-8"))
        return True
    except Exception:
        return False


class KeyManager:
    """Manages the server's Ed25519 key pair, persisting to disk."""

    def __init__(self, data_dir: str) -> None:
        self.data_dir = Path(data_dir)
        self.keys_path = self.data_dir / "keys.json"
        self.private_key: Ed25519PrivateKey
        self.public_key: Ed25519PublicKey
        self._load_or_generate()

    def _load_or_generate(self) -> None:
        """Load keys from disk or generate and save a new pair."""
        if self.keys_path.exists():
            with open(self.keys_path) as f:
                data = json.load(f)
            self.private_key = private_key_from_hex(data["private_key_hex"])
            self.public_key = self.private_key.public_key()
            logger.info("Loaded existing key pair from %s", self.keys_path)
        else:
            self.private_key, self.public_key = generate_keypair()
            self._save()
            logger.info("Generated new key pair, saved to %s", self.keys_path)

    def _save(self) -> None:
        """Persist the key pair to disk."""
        os.makedirs(self.data_dir, exist_ok=True)
        data = {
            "private_key_hex": private_key_to_hex(self.private_key),
            "public_key_multibase": public_key_to_multibase(self.public_key),
        }
        with open(self.keys_path, "w") as f:
            json.dump(data, f, indent=2)

    @property
    def public_key_multibase(self) -> str:
        """Return the public key as a multibase string."""
        return public_key_to_multibase(self.public_key)
