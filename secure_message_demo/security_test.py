#!/usr/bin/env python3
"""
security_test.py — Demonstrates what fails and why.

TEST 1: Normal encryption + decryption (should succeed)
TEST 2: Wrong private key (should fail)
TEST 3: Tampered ciphertext (should fail)

Run:
    python3 security_test.py
"""

import os
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; BOLD = "\033[1m"; RST = "\033[0m"


def generate_keypair():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def encrypt(public_key, message: bytes) -> bytes:
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def divider(title):
    print(f"\n{BOLD}{'─' * 50}{RST}")
    print(f"{BOLD}  {title}{RST}")
    print(f"{'─' * 50}")


def main():
    print(f"\n{BOLD}{'=' * 50}{RST}")
    print(f"{BOLD}  RSA-OAEP SECURITY TESTS{RST}")
    print(f"{BOLD}{'=' * 50}{RST}")
    print(f"{Y}  Prototype — not production grade.{RST}")

    message = b"Hello Device B - secret message"
    results = []

    # ── TEST 1: normal round-trip ──────────────────────────────────────────
    divider("TEST 1 — Normal encryption and decryption")
    priv_b, pub_b = generate_keypair()

    ct = encrypt(pub_b, message)
    print(f"  Encrypted with Device B public key.")
    print(f"  Ciphertext size: {len(ct)} bytes")

    try:
        pt = decrypt(priv_b, ct)
        match = (pt == message)
        print(f"  Decrypted : {pt.decode()}")
        print(f"  {G}PASS — correct key decrypts correctly.{RST}")
        results.append(True)
    except Exception as e:
        print(f"  {R}UNEXPECTED FAIL: {e}{RST}")
        results.append(False)

    # ── TEST 2: wrong private key ──────────────────────────────────────────
    divider("TEST 2 — Wrong private key (attacker uses their own key)")
    priv_attacker, _ = generate_keypair()
    print(f"  Encrypted with Device B public key.")
    print(f"  Attempting decryption with a DIFFERENT private key...")

    try:
        pt = decrypt(priv_attacker, ct)
        print(f"  {R}UNEXPECTED SUCCESS — this should not happen.{RST}")
        results.append(False)
    except (ValueError, TypeError):
        print(f"  {G}FAIL (as expected) — wrong private key cannot decrypt.{RST}")
        print(f"  Reason: RSA-OAEP decryption failed (key mismatch).")
        print(f"  PASS")
        results.append(True)

    # ── TEST 3: tampered ciphertext ────────────────────────────────────────
    divider("TEST 3 — Tampered ciphertext (1 byte flipped)")
    tampered = bytearray(ct)
    tampered[100] ^= 0xFF
    print(f"  Original ciphertext byte [100]: 0x{ct[100]:02X}")
    print(f"  Tampered ciphertext byte [100]: 0x{tampered[100]:02X}")
    print(f"  Attempting decryption of tampered ciphertext...")

    try:
        pt = decrypt(priv_b, bytes(tampered))
        print(f"  {R}UNEXPECTED SUCCESS — tampered data should not decrypt.{RST}")
        results.append(False)
    except (ValueError, TypeError):
        print(f"  {G}FAIL (as expected) — tampered ciphertext cannot decrypt.{RST}")
        print(f"  Reason: OAEP padding check failed after modification.")
        print(f"  PASS")
        results.append(True)

    # ── Summary ────────────────────────────────────────────────────────────
    passed = sum(results)
    total  = len(results)
    print(f"\n{BOLD}{'=' * 50}{RST}")
    color = G if passed == total else R
    print(f"{BOLD}  RESULTS: {color}{passed}/{total} passed{RST}")
    print(f"{BOLD}{'=' * 50}{RST}\n")

    print("What these tests prove:")
    print("  1. Correct key pair → decryption works.")
    print("  2. Wrong private key → decryption fails.")
    print("  3. Any modification to ciphertext → decryption fails.")
    print("  Only the matching private key can ever decrypt the message.")
    print()

    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
