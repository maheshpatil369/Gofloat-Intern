# Guidance — Secure UART from the Basics (with examples)

This is a learn-by-doing walk-through. It assumes you know a little Python and
nothing about cryptography. Every concept comes with a tiny runnable example.
By the end you will understand **exactly** what [`secure_uart.py`](secure_uart.py)
does and why each line is there.

> Reminder: this is a **prototype for learning and research**. It is not
> production-ready and must never be called "military grade" or "100% secure".

---

## 0. The big idea in one picture

Two devices are joined by two wires (a UART). Anyone can tap those wires. We
want Device B to be sure a message:

1. **came from the real Device A** (authenticity),
2. **was not changed in transit** (integrity),
3. **cannot be read by a tapper** (confidentiality),
4. **is not an old message replayed** (freshness).

We get 1–3 from **AEAD** (one crypto function) and 4 from a **counter**.

```
A:  "fire laser" --[encrypt+sign]--> gibberish+tag --wire--> B --[check+decrypt]--> "fire laser"
                                              ^
                                     attacker sees only gibberish,
                                     and cannot change or forge it
```

---

## 1. Setup

```bash
cd secure_uart_demo
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 secure_uart.py          # see it all work end to end
```

We use the **`cryptography`** library. **Rule #1 of crypto engineering: never
write your own crypto primitives.** Use audited libraries. We do.

---

## 2. Symmetric keys — the shared secret

"Symmetric" means both sides use the **same** secret key. If you have the key
you can encrypt and decrypt; if you don't, you can't do either.

A key is just random bytes. For AES-256 / ChaCha20 it is **32 bytes** (256 bits).
Generate it with a **cryptographically secure** random source — `os.urandom`,
**not** `random.random()` (which is predictable).

```python
import os
key = os.urandom(32)        # 32 random bytes = a 256-bit key
print(len(key), key.hex())
# 32  e3a1...  (different every time)
```

> ❌ Never do `key = b"my_secret_password_123"`. Never hard-code keys. A key is
> random bytes from a CSPRNG, provisioned to the device — not a password.

---

## 3. Encryption alone is NOT enough (the core lesson)

A beginner thinks "encrypt = secure". Watch why that's false. Imagine a simple
XOR "cipher" (don't use this — it's a teaching toy):

```python
msg = bytearray(b"OPEN THE DOOR")
key = 0x42
ct  = bytearray(b ^ key for b in msg)     # "encrypt"
# attacker flips one ciphertext byte without knowing the message:
ct[0] ^= 0x1E
pt  = bytes(b ^ key for b in ct)          # receiver "decrypts"
print(pt)        # b'QPEN THE DOOR'  <-- changed, and no error was raised!
```

The receiver had no way to know the message was altered. Encryption gives
**secrecy**, not **integrity**. This is the single most important beginner
insight. The fix is **AEAD**.

---

## 4. AEAD — encryption + authentication in one step

**AEAD** = *Authenticated Encryption with Associated Data*. One function gives
you confidentiality **and** a 16-byte **authentication tag** that detects any
tampering. We use **ChaCha20-Poly1305** (an IETF standard, RFC 8439).

```python
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os

key   = ChaCha20Poly1305.generate_key()   # 32 bytes
aead  = ChaCha20Poly1305(key)
nonce = os.urandom(12)                     # 12 bytes, must be UNIQUE per message
msg   = b"OPEN THE DOOR"
aad   = b"header-stuff-that-is-public-but-protected"

ct = aead.encrypt(nonce, msg, aad)         # ct = ciphertext + 16-byte tag
print(len(msg), "->", len(ct), "bytes")    # 13 -> 29  (16 extra = the tag)

# Receiver with the same key, nonce, aad gets the message back:
pt = aead.decrypt(nonce, ct, aad)
print(pt)                                  # b'OPEN THE DOOR'
```

Now tamper with it:

```python
from cryptography.exceptions import InvalidTag
bad = bytearray(ct); bad[0] ^= 0x01        # flip ONE bit of the ciphertext
try:
    aead.decrypt(nonce, bytes(bad), aad)
except InvalidTag:
    print("REJECTED: tampering detected")  # <-- this is what happens
```

**That `InvalidTag` is the whole point.** Change any bit of the ciphertext, the
tag, or the AAD, and decryption refuses. Compare to §3 where the change slipped
through silently.

### The four inputs, explained

- **key** — the shared secret (32 bytes). Secrecy of everything depends on it.
- **nonce** — "number used once". A 12-byte value that must be **unique** for
  each message under a given key. More on this in §5.
- **plaintext** — your actual message. This is what gets encrypted.
- **associated data (AAD)** — extra data that is **authenticated but not
  encrypted**. We put the packet header here, so routing fields (type, sequence,
  sender) stay readable yet cannot be tampered with.

The output is `ciphertext || tag`. The `cryptography` library appends the
16-byte tag to the ciphertext for you.

---

## 5. Nonces — the one rule you must never break

> **Never use the same (key, nonce) pair twice.**

With ChaCha20-Poly1305 and AES-GCM, reusing a nonce under the same key is
**catastrophic**: it can leak your plaintext and even let an attacker forge
messages. So how do we guarantee uniqueness on a tiny device whose random-number
generator might be weak?

**Answer: don't use random nonces — build them from a counter.**

```python
import struct
def derive_nonce(sender_id, seq):
    # 2 bytes sender + 2 bytes zero + 8 bytes counter = 12 bytes
    return struct.pack(">H", sender_id) + b"\x00\x00" + struct.pack(">Q", seq)

print(derive_nonce(0x00A1, 1).hex())   # 00a100000000000000000001
print(derive_nonce(0x00A1, 2).hex())   # 00a100000000000000000002  (different!)
```

As long as the counter **always increases and never repeats**, the nonce is
always unique. Including the `sender_id` means two devices sharing a key still
never collide. This is why the counter must survive a reboot in a real device —
see §8.

---

## 6. The packet — turning fields into bytes on the wire

UART sends raw bytes. We need an agreed byte layout so the receiver can pull the
fields back out. We use `struct` for fixed, portable, big-endian framing.

```python
import struct
MAGIC = b"\x53\x55"           # "SU", a marker so B can find the frame start
# >  = big-endian; 2s=2 bytes, B=1 byte, H=2, Q=8
header = struct.pack(">2sBBBHBQ12sH",
    MAGIC, 1, 1, 1, 0x00A1, 1, 42,        # magic,ver,type,flags,sender,key_id,seq
    b"\x00"*12, 29)                       # nonce(12), ciphertext length
print(len(header), header.hex())          # 30-byte header
```

Our full frame is:

```
MAGIC | VERSION | TYPE | FLAGS | SENDER | KEY_ID | SEQ | NONCE | CT_LEN | CIPHERTEXT+TAG | CRC
```

Every field earns its place — see the table in [docs/DESIGN.md §5](docs/DESIGN.md#5-packet-format).
Two to note:

- **CT_LEN** tells the receiver exactly how many ciphertext bytes follow, so it
  reads the right amount and can bounds-check safely.
- **CRC32** is a checksum for detecting **accidental** line noise. It is **not
  security** — an attacker just recomputes it. Only the AEAD tag stops attackers.

---

## 7. Parsing hostile input without crashing

The receiver's parser sees bytes an **attacker** fully controls. It must reject
anything malformed **before** doing crypto, and it must never crash. The key
defensive checks (see `parse_packet` in the code):

```python
# 1. Is it even long enough to contain a header + a tag?
if len(frame) < HEADER_LEN + 16: raise PacketError("too short")
# 2. Right magic and version?
if magic != MAGIC: raise PacketError("bad magic")
# 3. Does the declared length match the actual bytes? (stops integer/overflow tricks)
if len(frame) != HEADER_LEN + ct_len + crc_size: raise PacketError("length mismatch")
```

Try feeding it garbage and watch it refuse calmly:

```python
import secure_uart as su
_, b, _ = su.new_pair()
for junk in (b"", b"\x00", b"not a packet", su.os.urandom(200)):
    ok, reason, _ = b.receive(junk)
    print(ok, reason)     # all False, clean reasons, no exception
```

**Rule: every byte from the wire is guilty until the AEAD tag proves it
innocent.**

---

## 8. Replay protection — stopping "record and resend"

Even a perfectly authentic packet can be **captured and replayed** by an
attacker. AEAD can't help — the tag is valid. We use the **sequence number**.

The receiver remembers the highest sequence it has accepted and a bitmap of the
recent ones (an IPsec-style **sliding window**, RFC 4303):

```python
import secure_uart as su
w = su.ReplayWindow(window=64)
print(w.check_and_update(1))   # True  (new)
print(w.check_and_update(2))   # True  (new)
print(w.check_and_update(1))   # False (duplicate -> replay!)
print(w.check_and_update(5))   # True  (new, gap is fine = lost packets)
print(w.check_and_update(3))   # True  (out of order but fresh, inside window)
print(w.check_and_update(3))   # False (now it's a duplicate)
```

| Case | Result |
|------|--------|
| duplicate | rejected |
| old (below window) | rejected |
| out-of-order, inside window, first time | accepted |
| gap / packet loss | allowed |

**Reboot caveat:** the counter is also the nonce source (§5). If a reboot reset
it to 0, nonces would repeat — forbidden. So a real device must **persist the
counter to flash**, or **derive a fresh key each boot**. The PoC runs as one
long-lived process, so it sidesteps this; the design doc calls it out for
hardware.

**Why not timestamps?** Clocks drift and reset, and an attacker can replay
inside the allowed skew. A counter is the reliable mechanism; a timestamp can
only assist.

---

## 9. Putting it together — the send/receive path

Sender (`SenderDevice.send`):

```
seq += 1                                  # fresh, never-reused counter
nonce = derive_nonce(sender_id, seq)      # unique nonce from the counter
aad   = header_bytes                      # authenticate the header
ct    = aead.encrypt(nonce, payload, aad) # ciphertext + 16-byte tag
frame = header + ct + crc                 # lay out the bytes
uart.write(frame)
```

Receiver (`ReceiverDevice.receive`) — order matters, cheap/safe checks first:

```
1 parse + structural validation   (reject malformed, no crash)
2 CRC check                        (catch accidental corruption)
3 known key_id?                    (do we even have this key?)
4 anti-replay PEEK                 (duplicate/old? reject early)
5 nonce matches (sender, seq)?     (block nonce-misuse tricks)
6 AEAD verify + decrypt            (THE trust gate; InvalidTag -> reject)
7 commit the replay window         (only now that the tag proved authenticity)
```

Step 7 is subtle and important: we update the replay window **only after** the
tag verifies, so a forged packet can't "use up" a sequence number and block a
future legitimate one.

---

## 10. Run the attack suite and read the output

```bash
python3 secure_uart.py
```

You will see 9 tests. Here is what each proves:

| Test | What we do | Expected | What it proves |
|------|-----------|----------|----------------|
| 1 | normal message | ACCEPTED | the happy path works |
| 2 | flip a ciphertext byte (and fix the CRC) | REJECTED (auth) | AEAD integrity, not CRC, is the guard |
| 3 | modify the auth tag | REJECTED (auth) | the tag itself is protected |
| 4 | replay an old valid frame | REJECTED (replay) | sequence window works |
| 5 | wrong key | REJECTED (auth) | no key → no access |
| 6 | lie about the length | REJECTED (malformed) | parser bounds-checks |
| 7 | random garbage | no crash | defensive parsing |
| 8 | duplicate sequence | REJECTED (replay) | duplicates caught |
| 9 | two sends | unique nonces | nonce reuse is structurally impossible |

Test 2 is the clincher: we flip a ciphertext byte **and recompute a valid CRC**,
so the only thing left to catch it is the cryptographic tag — and it does.

---

## 11. Try it yourself — small exercises

1. **Change the algorithm.** In `new_pair()` pass
   `algorithm="aes-256-gcm"` and re-run. Everything still passes — the layering
   let you swap the cipher without touching packets or transport.

2. **Prove confidentiality.** Print the frame hex in Test 1 (default) and search
   for your plaintext in it — you won't find it; it's encrypted.

3. **Break replay on purpose.** Temporarily make `ReplayWindow.check_and_update`
   always return `True` and watch Test 4 and Test 8 start failing (ACCEPTED when
   they should be REJECTED). Revert it. This shows the control is load-bearing.

4. **Real UART (optional).** Install `pyserial`, replace `SimulatedUART` with a
   `serial.Serial("/dev/ttyUSB0", 115200)` on two boards (or a USB-UART loopback)
   and nothing above the transport changes.

---

## 12. What you now understand

- Why **encryption alone is not enough**, and what the **authentication tag**
  adds (§3–§4).
- What a **nonce** is and the **never-reuse** rule, solved with a counter (§5).
- How a **binary packet** is laid out and parsed **safely** (§6–§7).
- How **replay protection** works and why it needs a **persistent counter** (§8).
- The exact **order of receive-side checks** and why order matters (§9).
- How to **prove** each control with the attack suite (§10).

Next: read [docs/DESIGN.md](docs/DESIGN.md) for the full threat model, crypto
comparison, key-management design, ROS 2 integration, and the MCU migration plan.
And remember the honest framing: **prototype ≠ production ≠ safety-critical /
defence deployment.**
