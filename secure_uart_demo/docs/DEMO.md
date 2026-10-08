# Demo Script — Senior Engineer Walk-Through (5–10 minutes)

This is the exact sequence to run for a senior engineer review.
It demonstrates the full secure communication pipeline and all key attacks.

---

## Setup (do this first)

```bash
cd secure_uart_demo
# Confirm the library is present:
python3 -c "from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305; print('OK')"
```

---

## Step 1 — Start Device B (the receiver)

**Terminal 1:**
```bash
python3 src/device_b.py
```

Device B will:
- Generate a 32-byte key and save it to `.dev_key.bin`
- Bind a socket on `127.0.0.1:9999` (simulated UART)
- Wait for Device A to connect

**What to say:**  
*"This is Device B — the receiver. It starts first because it plays the role
of the UART listener. In a real system this would be the MCU waiting on its RX
pin. It just generated a pre-shared key and saved it to a file that Device A
will load. In production, this would happen in a secure provisioning facility —
not a file. It is now waiting for an incoming connection, just like a UART
waits for bytes on the RX line."*

---

## Step 2 — Start Device A (the sender)

**Terminal 2:**
```bash
python3 src/device_a.py
```

Device A will:
- Load the key from `.dev_key.bin`
- Connect to Device B over the simulated UART (socket)
- Wait for your first message

**What to say:**  
*"This is Device A — the sender. It loaded the same pre-shared key. Note that
the two programs are running in completely separate processes. Device A has no
decrypt function — it only encrypts and transmits."*

---

## Step 3 — Send a normal message

In Terminal 2, type:
```
HELLO DEVICE B
```

**Walk through the Device A output with the engineer:**

- `Plaintext` — the original message, clear
- `Nonce` — derived from `(sender_id, sequence_number)`, unique per message
- `Sequence` — increments every message; used for replay protection
- `Ciphertext (payload, no tag)` — the message is now unreadable
- `Authentication tag` — 16 bytes that prove the packet came from the key holder
- `Full packet (HEX)` — every byte that travels over the wire

**Walk through Device B output:**
- It received the same hex bytes
- Checked magic bytes, version, length
- Checked the sequence was fresh (not a replay)
- Verified the nonce matches `(sender, seq)`
- Verified the AEAD tag — the packet is authentic and untampered
- Decrypted and displayed the original message

**What to say:**  
*"The plaintext never crossed the wire in the clear. The AEAD operation
gives us confidentiality, integrity, and authentication in one step. The
16-byte tag binds every header field to the encrypted payload — change any
bit and decryption refuses."*

---

## Step 4 — Send a second message

Type:
```
TEMP=35.4,STATUS=ACTIVE
```

Point out that `Sequence: 2` and the nonce is different from the first message.

**What to say:**  
*"Every message gets a new nonce. We derive it from the sequence counter so
it's guaranteed unique — no dependency on random number generator quality,
which matters on a bare-metal MCU."*

---

## Step 5 — Attack demonstration

Press Ctrl+C to exit Device A, then:

**Terminal 2:**
```bash
python3 attack_demo.py
```

Walk through each test:

| Test | What happens | What to say |
|------|-------------|-------------|
| TEST 1 — Normal | ACCEPTED | The baseline |
| TEST 2 — Flip ciphertext byte | REJECTED: AUTHENTICATION FAILED | We also recomputed the CRC to prove it is the AEAD tag, not the CRC, doing the rejecting |
| TEST 3 — Modify auth tag | REJECTED: AUTHENTICATION FAILED | Even tampering with the tag itself is detected |
| TEST 4 — Replay | REJECTED: replay/duplicate | The sequence window catches old packets |
| TEST 5 — Wrong key | REJECTED: AUTHENTICATION FAILED | Without the key, nothing gets through |
| TEST 6 — Malformed/garbage | PASS (no crash) | Defensive parser, attacker cannot crash the receiver |
| TEST 7 — Duplicate seq | REJECTED: replay/duplicate | The sliding window tracks every accepted sequence |

**Key point for TEST 2:**  
*"We flipped a ciphertext byte and then recomputed a valid CRC. So the CRC
said 'fine'. But the AEAD tag said 'rejected'. This proves that CRC is
error-detection only — it is not a security mechanism. An attacker can always
recompute a CRC. The AEAD tag requires the key."*

---

## Step 6 — Run all unit tests

```bash
python3 -m pytest tests/ -v
```

Expected: `35 passed`.

---

## Step 7 — Real UART (if hardware is available)

If two USB-UART adapters are connected:

Terminal 1:
```bash
python3 src/device_b.py --port /dev/ttyUSB1 --baudrate 115200
```

Terminal 2:
```bash
python3 src/device_a.py --port /dev/ttyUSB0 --baudrate 115200
```

No code changes — only the transport changes. The security protocol is
transport-agnostic.

---

## Step 8 — Architecture summary (2-minute explanation)

```
Device A                                   Device B
──────────────────────────────────────     ──────────────────────────────────
Application (plaintext message)
    ↓
Message layer (type, seq, sender id)
    ↓
Security layer                             Security layer
  • derive nonce(sender, seq)                • verify nonce(sender, seq)
  • AEAD encrypt(key, nonce, msg, aad)  →    • AEAD decrypt + verify tag
  • outputs: ciphertext + 16-byte tag        • fails loudly on any tamper
    ↓
Packet layer                               Packet layer
  • MAGIC | VER | TYPE | SENDER |            • parse fields
    SEQ | NONCE | CT_LEN |                   • check magic, version, length
    CIPHERTEXT+TAG | CRC                     • CRC check (accidental errors)
    ↓
Transport layer                            Transport layer
  • socket (simulated UART)            →    • socket listener
  • pyserial (real UART)                    • pyserial (real UART)
```

**What to say:**  
*"Each layer has one job. The crypto layer does not know about packets. The
packet layer does not know about crypto. The transport can be replaced from
simulated to real UART without changing anything above it. This is deliberately
structured so each layer can be independently tested — and we have 35 tests
that prove it."*

---

## MCU migration path (1-minute close)

*"When this moves to a real MCU: the security protocol stays the same. We swap
`ChaCha20Poly1305` from the Python `cryptography` library for an equivalent on
the MCU — either the hardware AES block with AES-GCM, or a vetted software
ChaCha20 library. The key moves from a file into protected flash or a secure
element. The sequence counter gets written to flash so it survives reboot —
because a reset counter means nonce reuse, which breaks AEAD security. The
transport becomes a DMA-driven UART peripheral. None of that changes the
protocol design above Layer 4."*

---

## What this prototype does NOT cover

Be honest about limits:

- No key agreement protocol (pre-shared key only)
- No secure boot or firmware signing
- No side-channel protection (power/EM analysis)
- No debug-port lockout
- File-based key storage is for PoC only — not production
- Physical device compromise defeats the cryptography

These are real production requirements but out of scope for this PoC layer.
