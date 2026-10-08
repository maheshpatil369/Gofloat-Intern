# Secure UART Demo

Two independent Python processes communicating over an encrypted, authenticated,
replay-protected binary protocol over a simulated UART link.

> ⚠️ **Security research / engineering prototype.**
> Not production, not safety-critical, not defence-grade.

---

## Quick start

```bash
cd secure_uart_demo

# Terminal 1 — start receiver FIRST (generates the shared key)
python3 src/device_b.py

# Terminal 2 — start sender
python3 src/device_a.py
# type a message and press Enter
```

```bash
# Attack demonstration (self-contained, no devices needed)
python3 attack_demo.py

# All unit tests
python3 -m pytest tests/ -v
```

---

## Project structure

```
src/
  config.py      protocol constants, key file helpers
  crypto.py      AeadCipher (ChaCha20-Poly1305 / AES-256-GCM), derive_nonce
  packet.py      build_packet(), parse_packet(), PacketError
  replay.py      ReplayWindow (IPsec-style sliding window, RFC 4303)
  transport.py   SocketClientTransport, SocketServerTransport, UartTransport
  device_a.py    SENDER — user input → encrypt → transmit
  device_b.py    RECEIVER — recv → validate → auth → decrypt → display

tests/
  test_crypto.py   9 tests (encrypt/decrypt, tamper, wrong key, nonce)
  test_packet.py   9 tests (build/parse, magic, length, CRC)
  test_replay.py   8 tests (window, duplicate, out-of-order, gap)
  test_security.py 9 tests (end-to-end: tamper, replay, wrong key, no crash)

docs/
  ARCHITECTURE.md   layer diagram + Mermaid + block explanations
  DEMO.md           step-by-step senior-engineer demo script
  DESIGN.md         full engineering spec (threat model, crypto comparison, etc.)
  GUIDANCE.md       from-basics tutorial with worked examples

attack_demo.py     7 attack tests: normal, tamper payload, tamper tag,
                   replay, wrong key, malformed, duplicate seq
```

---

## What the protocol does

```
DEVICE A (separate process)           DEVICE B (separate process)
────────────────────────────          ────────────────────────────
user types a message
seq += 1
nonce = derive(sender_id, seq)        waiting on socket/UART
AEAD encrypt + 16-byte tag
build binary packet
send over socket ─────────────────────────────────────> recv frame
                                      parse + validate header
                                      check CRC (accidental errors)
                                      check seq against replay window
                                      verify nonce == derive(sender,seq)
                                      AEAD verify tag + decrypt
                                      commit replay window
                                      display plaintext
```

Device A **never calls decrypt**. Device B **never sees plaintext until after
the authentication tag verifies**.

---

## Real UART (optional)

```bash
# Device B on one machine / board
python3 src/device_b.py --port /dev/ttyUSB1 --baudrate 115200

# Device A on the other
python3 src/device_a.py --port /dev/ttyUSB0 --baudrate 115200
```

No protocol code changes — only the transport layer switches.

---

## Algorithm

**Default: ChaCha20-Poly1305 (RFC 8439)** — fast in software, no hardware AES
required, 16-byte authentication tag, IETF standard. Also selectable:
AES-256-GCM (NIST SP 800-38D) for MCUs with a hardware AES block.

Crypto is from the audited `cryptography` library. **No hand-rolled primitives.**

---

## Test results

```
35 passed in 0.08s
```

All 7 attack tests behave as expected.

---

## What this does NOT protect against

Physical device compromise, stolen keys, unsigned firmware, side-channel
attacks, debug-port access, supply-chain tampering. Those require secure boot,
firmware signing, a secure element, and debug-port lockout — documented in
[docs/DESIGN.md](docs/DESIGN.md) but out of scope for this PoC.
