#!/usr/bin/env python3
"""
device_a.py — SENDER

Device A:
  1. Loads Device B's PUBLIC key.
  2. Asks user for a message.
  3. Encrypts using RSA-OAEP (SHA-256).
  4. Saves the ciphertext to encrypted_message.bin.

Device A NEVER decrypts. It only encrypts.
"""

import os
import sys
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

PUBLIC_KEY_F   = os.path.join(os.path.dirname(__file__), "keys", "public_key.pem")
CIPHERTEXT_F   = os.path.join(os.path.dirname(__file__), "encrypted_message.bin")


def load_public_key():
    if not os.path.exists(PUBLIC_KEY_F):
        print("ERROR: keys/public_key.pem not found.")
        print("  Run:  python3 generate_keys.py")
        sys.exit(1)
    with open(PUBLIC_KEY_F, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def hex_fmt(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        lines.append("  " + " ".join(f"{b:02X}" for b in chunk))
    return "\n".join(lines)


def main():
    print()
    print("=" * 44)
    print("  DEVICE A  —  SENDER")
    print("=" * 44)
    print()

    public_key = load_public_key()
    print("  Loaded Device B public key from keys/public_key.pem")
    print()

    try:
        message = input("Enter message: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        sys.exit(0)

    if not message:
        print("No message entered.")
        sys.exit(1)

    print()
    print("Original message:")
    print(f"  {message}")
    print()
    print("Encrypting using Device B PUBLIC KEY (RSA-OAEP, SHA-256)...")
    print()

    ciphertext = public_key.encrypt(
        message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    print("Encrypted message (HEX):")
    print(hex_fmt(ciphertext))
    print()
    print(f"  Size: {len(ciphertext)} bytes")
    print()

    with open(CIPHERTEXT_F, "wb") as f:
        f.write(ciphertext)

    print(f"Encrypted message saved to: encrypted_message.bin")
    print()
    print("  NOTE: This file represents the communication channel.")
    print("  In a real system this would travel over UART, network, etc.")
    print()
    print("  Device A's job is DONE. It cannot decrypt this message.")
    print("  Run device_b.py to decrypt.")
    print()


if __name__ == "__main__":
    main()
