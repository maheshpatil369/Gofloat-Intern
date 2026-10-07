# Secure UART Demo

A Proof-of-Concept for **secure communication between two embedded-style
devices** over a UART/serial link: authenticated encryption, replay
protection, and a defensively-parsed binary packet format.

> ⚠️ **Status: security research / engineering prototype.**
> This is **not** a production, safety-critical, or defence-grade system. It is
> a technically sound PoC meant to be reviewed and challenged by a senior
> engineer. Do not call it "military grade" or "100% secure" — it is neither.
> See [What this does *not* protect against](#what-this-does-not-protect-against).

---

## The three files to read, in order

| File | What it is |
|------|------------|
| **[GUIDANCE.md](GUIDANCE.md)** | Tutorial from first principles, with worked examples. **Start here if you are new to this.** |
| **[docs/DESIGN.md](docs/DESIGN.md)** | The full engineering spec: architecture, packet format, crypto comparison, threat model, key management, ROS 2, MCU migration. |
| **[secure_uart.py](secure_uart.py)** | The single, self-contained, runnable implementation + attack tests. |

## Run it

```bash
cd secure_uart_demo
python3 -m venv .venv && source .venv/bin/activate      # optional
pip install -r requirements.txt
python3 secure_uart.py            # full demo + 8 attack tests
python3 secure_uart.py --quiet    # skip the hex dump
```

Expected: `TEST 1` is accepted, `TEST 2–9` are all safely rejected, and the
summary prints `Security tests passed: 8/8`.

## What it demonstrates

```
DEVICE A  →  serialize  →  AEAD encrypt + authenticate  →  packetize  →  UART
DEVICE B  →  parse  →  validate  →  anti-replay  →  verify + decrypt  →  app
```

- **Confidentiality + Integrity + Authentication** in one step via an AEAD
  (ChaCha20-Poly1305, RFC 8439; AES-256-GCM also selectable).
- **Replay protection** via a monotonic sequence counter and a sliding window.
- **Deterministic nonces** derived from `(sender_id, sequence)` so a nonce is
  never reused — the one unforgivable mistake with AEAD.
- **Defensive packet parsing** that never crashes on hostile input.
- An **attack suite** (tamper / replay / wrong-key / malformed / nonce-reuse)
  that proves each control actually fires.

## What this does *not* protect against

Cryptographic communication is one layer. It does **not** by itself defend
against: physical device compromise, stolen keys, malicious/compromised
firmware, side-channel and fault-injection attacks, open debug ports (JTAG/SWD),
or supply-chain tampering. Those need secure boot, firmware signing, a secure
element, debug-port lockout, and process controls. See the threat model in
[docs/DESIGN.md](docs/DESIGN.md).
