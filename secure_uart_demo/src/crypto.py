import struct
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.exceptions import InvalidTag

from config import NONCE_LEN, TAG_LEN, KEY_LEN

__all__ = ["AeadCipher", "derive_nonce", "InvalidTag"]

ALGORITHM_NAMES = {
    "chacha20poly1305": "ChaCha20-Poly1305 (RFC 8439)",
    "aes-256-gcm":      "AES-256-GCM (NIST SP 800-38D)",
}


class AeadCipher:
    """
    Thin, audited-library wrapper for Authenticated Encryption with
    Associated Data (AEAD).

    Provides:
      Confidentiality  — payload encrypted
      Integrity        — any bit-flip detected
      Authentication   — only key-holder can produce a valid tag
      AAD binding      — header fields authenticated but not encrypted
    """

    def __init__(self, key: bytes, algorithm: str = "chacha20poly1305"):
        if len(key) != KEY_LEN:
            raise ValueError(f"key must be {KEY_LEN} bytes")
        self.algorithm = algorithm.lower()
        self.display_name = ALGORITHM_NAMES.get(self.algorithm, self.algorithm)
        if self.algorithm == "chacha20poly1305":
            self._impl = ChaCha20Poly1305(key)
        elif self.algorithm == "aes-256-gcm":
            self._impl = AESGCM(key)
        else:
            raise ValueError(f"unknown algorithm: {algorithm!r}")

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        if len(nonce) != NONCE_LEN:
            raise ValueError("nonce must be 12 bytes")
        return self._impl.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ct_and_tag: bytes, aad: bytes) -> bytes:
        if len(nonce) != NONCE_LEN:
            raise ValueError("nonce must be 12 bytes")
        return self._impl.decrypt(nonce, ct_and_tag, aad)


def derive_nonce(sender_id: int, seq: int) -> bytes:
    """
    Deterministic 96-bit nonce from (sender_id, sequence_number).

    GOLDEN RULE: a (key, nonce) pair must NEVER repeat.
    Using the monotonic sequence counter guarantees uniqueness without
    relying on RNG quality. The sender_id ensures two devices that share
    a key never produce the same nonce.

    Layout: sender_id (2B) || 0x0000 (2B) || seq (8B)
    """
    return struct.pack(">H2xQ", sender_id, seq)
