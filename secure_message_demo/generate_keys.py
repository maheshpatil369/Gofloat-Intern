#!/usr/bin/env python3
"""
generate_keys.py — Generate RSA 2048-bit key pair for Device B.

Run this ONCE before running device_a.py or device_b.py.

    python3 generate_keys.py
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

KEYS_DIR      = os.path.join(os.path.dirname(__file__), "keys")
PRIVATE_KEY_F = os.path.join(KEYS_DIR, "private_key.pem")
PUBLIC_KEY_F  = os.path.join(KEYS_DIR, "public_key.pem")


def main():
    os.makedirs(KEYS_DIR, exist_ok=True)

    print("Generating RSA 2048-bit key pair...")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Save private key — restricted permissions, NEVER print it
    with open(PRIVATE_KEY_F, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    os.chmod(PRIVATE_KEY_F, 0o600)

    # Save public key — safe to share
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(PUBLIC_KEY_F, "wb") as f:
        f.write(pub_pem)

    print()
    print("  Private key saved to : keys/private_key.pem  (SECRET — never share)")
    print("  Public key saved to  : keys/public_key.pem   (shareable)")
    print()
    print("Public key (safe to share with Device A):")
    print("-" * 50)
    print(pub_pem.decode())

    print("Key generation complete.")
    print()
    print("NEXT STEPS:")
    print("  1. python3 device_a.py   — Device A encrypts a message")
    print("  2. python3 device_b.py   — Device B decrypts it")
    print("  3. python3 security_test.py — see what attacks fail")


if __name__ == "__main__":
    main()
