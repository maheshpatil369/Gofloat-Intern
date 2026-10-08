#!/usr/bin/env python3
"""
device_b.py — RECEIVER

Device B:
  1. Loads its own PRIVATE key.
  2. Reads the encrypted message from encrypted_message.bin.
  3. Decrypts using RSA-OAEP (SHA-256).
  4. Displays the original message.

Only Device B can decrypt — it is the only holder of the private key.
"""

import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidKey, UnsupportedAlgorithm

PRIVATE_KEY_F  = os.path.join(os.path.dirname(__file__), "keys", "private_key.pem")
CIPHERTEXT_F   = os.path.join(os.path.dirname(__file__), "encrypted_message.bin")


def load_private_key():
    if not os.path.exists(PRIVATE_KEY_F):
        print("ERROR: keys/private_key.pem not found.")
        print("  Run:  python3 generate_keys.py")
        sys.exit(1)
    with open(PRIVATE_KEY_F, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def hex_fmt(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        lines.append("  " + " ".join(f"{b:02X}" for b in chunk))
    return "\n".join(lines)


def main():
    print()
    print("=" * 44)
    print("  DEVICE B  —  RECEIVER")
    print("=" * 44)
    print()

    private_key = load_private_key()
    print("  Loaded Device B private key (stays secret on this device)")
    print()

    if not os.path.exists(CIPHERTEXT_F):
        print("ERROR: encrypted_message.bin not found.")
        print("  Run device_a.py first to create it.")
        sys.exit(1)

    with open(CIPHERTEXT_F, "rb") as f:
        ciphertext = f.read()

    print("Encrypted message received from channel (encrypted_message.bin):")
    print()
    print("Ciphertext (HEX):")
    print(hex_fmt(ciphertext))
    print()
    print(f"  Size: {len(ciphertext)} bytes")
    print()
    print("Decrypting using Device B PRIVATE KEY (RSA-OAEP, SHA-256)...")
    print()

    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except (ValueError, TypeError) as e:
        print("Decryption FAILED.")
        print(f"  Reason: {e}")
        print()
        print("  This means:")
        print("  - Wrong private key was used, OR")
        print("  - The ciphertext was tampered with")
        print()
        sys.exit(1)

    print("Decrypted message:")
    print(f"  {plaintext.decode('utf-8')}")
    print()
    print("SUCCESS ✓")
    print()
    print("  The private key successfully decrypted the message.")
    print("  Device A never had access to this private key.")
    print()


if __name__ == "__main__":
    main()
