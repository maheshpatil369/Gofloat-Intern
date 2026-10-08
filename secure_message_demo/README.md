# Secure Message Demo — Public Key Encryption

A clean demonstration of public-key encryption between two devices using
RSA-OAEP with SHA-256.

> ⚠️ **Cryptographic proof-of-concept only.**
> Not production, not safety-critical, not military-grade.
> See "What this is NOT" at the bottom.

---

## Run it (3 steps)

```bash
cd secure_message_demo

# Step 1 — generate the key pair (once)
python3 generate_keys.py

# Step 2 — Device A encrypts a message
python3 device_a.py

# Step 3 — Device B decrypts it
python3 device_b.py

# Security tests (wrong key, tampered data)
python3 security_test.py
```

---

## Architecture

```
             DEVICE A
                |
          Plain Message
          "Hello Device B"
                |
                ↓
    Encrypt with B's PUBLIC KEY
    (RSA-OAEP, SHA-256)
                |
                ↓
       Encrypted Message
       (unreadable ciphertext)
                |
       Communication Channel
       (encrypted_message.bin)
       [In future: UART / network]
                |
                ↓
             DEVICE B
                |
    Decrypt with B's PRIVATE KEY
    (RSA-OAEP, SHA-256)
                |
                ↓
          Plain Message
          "Hello Device B"
```

---

## Concepts explained from basics

### 1. What is encryption?
Encryption converts readable data (plaintext) into unreadable data
(ciphertext). Only someone with the correct key can reverse it.

```
"Hello Device B"  →  encrypt  →  8A 3F 91 C2 ... (unreadable)
8A 3F 91 C2 ...   →  decrypt  →  "Hello Device B"
```

### 2. What is a public key?
A public key is like a **padlock**. You can give a copy of the open padlock
to anyone. They can lock (encrypt) a message with it. But they cannot unlock
it — only you can, because only you have the key.

- Safe to share with everyone
- Used to **encrypt** (lock)
- Cannot decrypt with it

### 3. What is a private key?
A private key is the **key to the padlock**. It must never leave Device B.

- Must remain secret on Device B
- Used to **decrypt** (unlock)
- If an attacker gets this, the whole system is broken

### 4. Why does Device A use Device B's public key?
Because Device A wants to send a message that **only Device B can read**.
If Device A encrypts with Device B's public key, only Device B's private key
can decrypt it.

### 5. What is RSA?
RSA is a widely used public-key cryptography algorithm. It relies on the
mathematical difficulty of factoring very large numbers. With a 2048-bit key,
the numbers are so large that brute-force is computationally infeasible with
today's hardware.

### 6. What is RSA-OAEP?
OAEP (Optimal Asymmetric Encryption Padding) is the correct way to use RSA
for encryption. It adds randomness so that the same plaintext produces
different ciphertext each time, and it includes integrity checks.

**Never use the older PKCS#1 v1.5 padding** — it has known vulnerabilities.

```python
# Correct
padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(), label=None)

# Wrong — do not use
padding.PKCS1v15()
```

### 7. Why SHA-256?
SHA-256 is used inside OAEP for the hash function. It is a well-tested,
collision-resistant hash function standardised by NIST.

### 8. Why 2048-bit RSA?
Larger key = harder to break by factoring. 2048-bit is the current minimum
standard for RSA (NIST SP 800-57). 3072-bit or 4096-bit give more margin.

### 9. Why must the private key stay secret?
If an attacker gets the private key, they can decrypt every past and future
message. There is no recovery except generating a new key pair and
re-provisioning.

### 10. Why is RSA not suitable for large messages directly?
RSA can only encrypt data smaller than its key size minus padding overhead.
For a 2048-bit (256-byte) key with OAEP-SHA256, the maximum plaintext is
about **190 bytes**.

For longer messages, use **hybrid encryption** (see below).

### 11. What is hybrid encryption?
Hybrid encryption combines the best of both worlds:

```
Device A
  |
  ├─ Generate random 32-byte session key
  ├─ Encrypt the message with AES-GCM (fast, any size)
  ├─ Encrypt the session key with RSA-OAEP (wraps the small key only)
  |
  → Send: [RSA-wrapped session key] + [AES-GCM ciphertext]

Device B
  |
  ├─ RSA-OAEP decrypt → session key
  ├─ AES-GCM decrypt (session key) → original message
```

This is how real systems work (TLS, Signal, PGP, etc.).

---

## How to explain this to your senior engineer

> *"Device B generates a 2048-bit RSA key pair. The public key is shared with
> Device A; the private key never leaves Device B. When Device A wants to
> send a confidential message, it encrypts the plaintext using Device B's
> public key via RSA-OAEP with SHA-256. Only the matching private key held by
> Device B can invert the operation, so even if an attacker intercepts the
> ciphertext or reads Device A's memory, they cannot recover the plaintext.*
>
> *RSA is used here to illustrate the public-key concept clearly. For a real
> embedded communication system I would use hybrid encryption — a symmetric
> AEAD algorithm such as AES-GCM or ChaCha20-Poly1305 encrypts the actual
> data, while RSA-OAEP protects the session key. This is faster, supports
> arbitrary payload sizes, and is how every real secure protocol (TLS, Signal)
> works under the hood."*

---

## Security tests

`security_test.py` proves three things:

| Test | What we do | Expected |
|------|-----------|----------|
| 1 | Correct key pair | Decryption succeeds |
| 2 | Wrong private key | Decryption fails |
| 3 | 1 byte flipped in ciphertext | Decryption fails (OAEP check) |

Run it:
```bash
python3 security_test.py
```

---

## Future: UART extension

**Current (this demo):**
```
Device A  →  encrypted_message.bin  →  Device B
              (file = the channel)
```

**Future:**
```
Device A                          Device B
Public Key                        Private Key
    ↓                                 ↓
RSA-OAEP Encrypt                 RSA-OAEP Decrypt
    ↓                                 ↑
Encrypted Packet ─── UART ───────→ Receiver
```

UART itself provides **no encryption**. The security comes entirely from the
RSA-OAEP layer above it. For embedded MCUs, hybrid encryption (RSA + AES-GCM)
is the production approach.

---

## What this is NOT

- Not production-ready
- Not defence or safety-critical grade
- Does not provide authentication of Device A (no signature — Device B cannot
  verify *who* sent the message, only *that* it was encrypted with the right key)
- Does not provide forward secrecy (use ECDH + AES-GCM for that)
- RSA key management here is file-based PoC only — production uses a secure
  element or HSM

The purpose is to demonstrate the **cryptographic concept** cleanly and
correctly, as a foundation to build on.
