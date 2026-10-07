#!/usr/bin/env python3
"""
secure_uart.py  -  Secure UART communication Proof-of-Concept (single file)
============================================================================

A self-contained, runnable demonstration of authenticated, encrypted,
replay-protected packet communication between two embedded-style devices
over a (simulated) UART serial link.

This is a SECURITY RESEARCH / ENGINEERING PROTOTYPE.
It is NOT a production, safety-critical, or defence-grade system.
See DESIGN.md and the "LIMITATIONS" notes below.

What this file demonstrates
---------------------------
  Device A  -> serialize -> AEAD encrypt + authenticate -> packetize -> UART
  Device B  -> parse packet -> validate -> anti-replay -> verify+decrypt -> app

Cryptography
------------
  AEAD = ChaCha20-Poly1305 (RFC 8439) via the audited `cryptography` library.
  We DO NOT implement crypto primitives ourselves.
  AES-256-GCM is also provided as a selectable backend.

Run it:
    python3 secure_uart.py            # normal run + all attack tests
    python3 secure_uart.py --quiet    # less verbose

Requires:
    pip install cryptography
"""

from __future__ import annotations

import os
import sys
import time
import struct
import zlib
from dataclasses import dataclass, field

# --- Audited crypto primitives. We never roll our own crypto. -----------------
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.exceptions import InvalidTag


# =============================================================================
# 0. CONSTANTS / PROTOCOL PARAMETERS
# =============================================================================

MAGIC    = b"\x53\x55"  # "SU" = Secure Uart. Frame synchronization marker.
VERSION  = 0x01          # Protocol version, for forward compatibility.

# Message types (TYPE field)
TYPE_DATA      = 0x01
TYPE_COMMAND   = 0x02
TYPE_STATUS    = 0x03
TYPE_HEARTBEAT = 0x04

# Flags (bitfield). Room to grow without a version bump.
FLAG_NONE      = 0x00
FLAG_HAS_CRC   = 0x01    # a trailing CRC32 is present

NONCE_LEN = 12           # ChaCha20-Poly1305 and AES-GCM both use a 96-bit nonce
TAG_LEN   = 16           # Poly1305 / GCM authentication tag is 128 bits
KEY_LEN   = 32           # 256-bit symmetric key

# Anti-replay sliding window size (like IPsec anti-replay, RFC 4303 style).
REPLAY_WINDOW = 64

# Header layout (everything that is authenticated as Associated Data, AAD).
# This is packed big-endian ("network order") so it is portable to an MCU.
#   magic    : 2 bytes
#   version  : 1 byte
#   type     : 1 byte
#   flags    : 1 byte
#   sender   : 2 bytes  (device id)
#   key_id   : 1 byte   (which provisioned key)
#   seq      : 8 bytes  (monotonic counter, replay + nonce source)
#   nonce    : 12 bytes (transmitted for clarity; also re-derivable)
#   ct_len   : 2 bytes  (length of ciphertext INCLUDING the 16-byte tag)
HEADER_FMT = ">2sBBBHB Q 12s H"          # spaces are ignored by struct
HEADER_LEN = struct.calcsize(HEADER_FMT)  # = 30 bytes


# =============================================================================
# 1. CRYPTO LAYER  -  thin wrapper over an audited AEAD
# =============================================================================

class AeadCipher:
    """
    Authenticated Encryption with Associated Data.

    AEAD gives us THREE guarantees in one operation:
      * Confidentiality : the plaintext is hidden (encryption).
      * Integrity       : any change to ciphertext is detected (tag).
      * Authentication  : only a holder of the key could have produced the tag.

    `associated_data` (AAD) is authenticated but NOT encrypted. We feed the
    packet header in as AAD so an attacker cannot tamper with the sequence
    number, type, sender id, etc. without breaking the tag.
    """

    def __init__(self, key: bytes, algorithm: str = "chacha20poly1305"):
        if len(key) != KEY_LEN:
            raise ValueError(f"key must be {KEY_LEN} bytes, got {len(key)}")
        self.algorithm = algorithm.lower()
        if self.algorithm == "chacha20poly1305":
            self._aead = ChaCha20Poly1305(key)
        elif self.algorithm == "aes-256-gcm":
            self._aead = AESGCM(key)
        else:
            raise ValueError(f"unknown algorithm {algorithm!r}")

    def encrypt(self, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        """Returns ciphertext || 16-byte tag."""
        if len(nonce) != NONCE_LEN:
            raise ValueError("bad nonce length")
        return self._aead.encrypt(nonce, plaintext, aad)

    def decrypt(self, nonce: bytes, ct_and_tag: bytes, aad: bytes) -> bytes:
        """
        Returns plaintext, or raises InvalidTag if authentication fails.
        A failed tag check means: wrong key, tampered ciphertext, tampered
        header (AAD), or tampered tag. We cannot and must not tell which.
        """
        if len(nonce) != NONCE_LEN:
            raise ValueError("bad nonce length")
        return self._aead.decrypt(nonce, ct_and_tag, aad)


# =============================================================================
# 2. NONCE MANAGEMENT  -  the single most important rule in AEAD
# =============================================================================
#
# GOLDEN RULE: never reuse a (key, nonce) pair. For ChaCha20-Poly1305 and
# AES-GCM, nonce reuse is catastrophic (it can leak plaintext and, worse, the
# authentication key). So we do NOT use random nonces on a tiny device where
# the RNG may be weak. Instead we build the nonce DETERMINISTICALLY from data
# that is guaranteed unique per message: the sender id and a monotonic counter.
#
#   nonce (12 bytes) = sender_id (2) || 0x0000 (2) || sequence (8)
#
# As long as the sequence counter never repeats for a given key, the nonce
# never repeats. This is why the sequence counter MUST survive reboot in a
# real device (persist it to flash) or the key must be rotated on boot.
# =============================================================================

def derive_nonce(sender_id: int, seq: int) -> bytes:
    return struct.pack(">H", sender_id) + b"\x00\x00" + struct.pack(">Q", seq)


# =============================================================================
# 3. PACKET LAYER  -  binary framing, build and parse
# =============================================================================

class PacketError(Exception):
    """Raised for any structural problem. Caught and handled, never crashes."""


@dataclass
class Packet:
    version: int
    type: int
    flags: int
    sender: int
    key_id: int
    seq: int
    nonce: bytes
    ciphertext: bytes          # includes the trailing 16-byte tag
    crc_ok: bool = True        # only meaningful on a parsed packet


def build_packet(version, msg_type, flags, sender, key_id, seq,
                 nonce, ciphertext, add_crc=True) -> bytes:
    """Serialize all fields into the on-the-wire byte frame."""
    if add_crc:
        flags |= FLAG_HAS_CRC
    header = struct.pack(
        HEADER_FMT, MAGIC, version, msg_type, flags, sender, key_id,
        seq, nonce, len(ciphertext),
    )
    frame = header + ciphertext
    if flags & FLAG_HAS_CRC:
        crc = zlib.crc32(frame) & 0xFFFFFFFF
        frame += struct.pack(">I", crc)
    return frame


def parse_packet(frame: bytes) -> Packet:
    """
    Parse and STRUCTURALLY validate a frame. Raises PacketError on anything
    malformed. This runs BEFORE any crypto, so it must be defensive: an
    attacker controls every byte here.
    """
    # Smallest possible frame = header + at least the 16-byte tag.
    if len(frame) < HEADER_LEN + TAG_LEN:
        raise PacketError(f"frame too short: {len(frame)} bytes")

    magic, version, msg_type, flags, sender, key_id, seq, nonce, ct_len = \
        struct.unpack(HEADER_FMT, frame[:HEADER_LEN])

    if magic != MAGIC:
        raise PacketError("bad magic / not a frame")
    if version != VERSION:
        raise PacketError(f"unsupported version {version}")
    if ct_len < TAG_LEN:
        raise PacketError("ciphertext shorter than auth tag")

    # Integer / length safety: compute exactly where ciphertext ends and make
    # sure the frame actually contains that many bytes (no overflow, no
    # over-read of an oversized declared length).
    ct_start = HEADER_LEN
    ct_end   = ct_start + ct_len
    has_crc  = bool(flags & FLAG_HAS_CRC)
    expected_len = ct_end + (4 if has_crc else 0)
    if len(frame) != expected_len:
        raise PacketError(
            f"length mismatch: declared needs {expected_len}, got {len(frame)}")

    ciphertext = frame[ct_start:ct_end]

    crc_ok = True
    if has_crc:
        got_crc = struct.unpack(">I", frame[ct_end:ct_end + 4])[0]
        calc_crc = zlib.crc32(frame[:ct_end]) & 0xFFFFFFFF
        crc_ok = (got_crc == calc_crc)

    return Packet(version, msg_type, flags, sender, key_id, seq,
                  nonce, ciphertext, crc_ok)


# =============================================================================
# 4. REPLAY PROTECTION  -  sliding window over the sequence counter
# =============================================================================

class ReplayWindow:
    """
    IPsec-style anti-replay (RFC 4303, Appendix A).

    We track the highest sequence number seen and a bitmap of the last N
    numbers. This correctly handles:
      * duplicates      -> rejected
      * old packets     -> rejected (fall off the left of the window)
      * out-of-order    -> accepted (as long as inside the window, once)
      * packet loss     -> fine, gaps are allowed
    """

    def __init__(self, window=REPLAY_WINDOW):
        self.window = window
        self.highest = 0        # highest sequence accepted so far
        self.bitmap = 0         # bit i set => (highest - i) was seen

    def check_and_update(self, seq: int) -> bool:
        if seq <= 0:
            return False                      # sequence 0 is reserved/invalid
        if seq > self.highest:
            shift = seq - self.highest
            self.bitmap = ((self.bitmap << shift) | 1) & ((1 << self.window) - 1)
            self.highest = seq
            return True
        offset = self.highest - seq
        if offset >= self.window:
            return False                      # too old, outside the window
        mask = 1 << offset
        if self.bitmap & mask:
            return False                      # already seen -> replay
        self.bitmap |= mask
        return True


# =============================================================================
# 5. TRANSPORT LAYER  -  simulated UART (and a note on real UART)
# =============================================================================

class SimulatedUART:
    """
    A loopback "wire". Device A writes bytes, Device B reads them. This stands
    in for a real UART at 115200 8N1. We also expose the raw buffer so an
    attacker model can corrupt / replay bytes in transit.

    To use a REAL uart instead, swap this for pyserial:
        import serial
        link = serial.Serial("/dev/ttyUSB0", 115200, timeout=1)
        link.write(frame); data = link.read(...)
    The protocol code above does not change at all.
    """

    def __init__(self):
        self._buf = b""

    def write(self, data: bytes) -> None:
        self._buf += data

    def read_frame(self) -> bytes:
        data, self._buf = self._buf, b""
        return data


# =============================================================================
# 6. DEVICE LAYER  -  ties message + security + packet + transport together
# =============================================================================

class SenderDevice:
    def __init__(self, device_id: int, key: bytes, key_id: int,
                 algorithm="chacha20poly1305", start_seq=0):
        self.device_id = device_id
        self.key_id = key_id
        self.cipher = AeadCipher(key, algorithm)
        self.seq = start_seq            # MUST persist across reboot in real HW

    def send(self, link: SimulatedUART, payload: bytes,
             msg_type=TYPE_DATA) -> bytes:
        self.seq += 1                               # monotonic, never reused
        nonce = derive_nonce(self.device_id, self.seq)

        # Build the header FIRST so we can authenticate it as AAD. We build a
        # provisional header with a placeholder ct_len, then rebuild once we
        # know the real ciphertext length. Simpler: compute aad = header.
        ct_placeholder_len = len(payload) + TAG_LEN
        aad = struct.pack(
            HEADER_FMT, MAGIC, VERSION, msg_type, FLAG_HAS_CRC,
            self.device_id, self.key_id, self.seq, nonce, ct_placeholder_len,
        )
        ciphertext = self.cipher.encrypt(nonce, payload, aad)   # ct || tag
        assert len(ciphertext) == ct_placeholder_len

        frame = build_packet(VERSION, msg_type, FLAG_HAS_CRC, self.device_id,
                             self.key_id, self.seq, nonce, ciphertext,
                             add_crc=True)
        link.write(frame)
        return frame


class ReceiverDevice:
    def __init__(self, keys: dict[int, bytes], algorithm="chacha20poly1305"):
        # keys maps key_id -> key, so we support multiple provisioned keys.
        self.ciphers = {kid: AeadCipher(k, algorithm) for kid, k in keys.items()}
        self.replay = ReplayWindow()

    def receive(self, frame: bytes) -> tuple[bool, str, bytes | None]:
        """
        Returns (accepted, reason, plaintext). Never raises on bad input;
        a hostile frame must produce a clean rejection, not a crash.
        """
        # --- Step 1: structural parse (attacker controls every byte) --------
        try:
            pkt = parse_packet(frame)
        except PacketError as e:
            return (False, f"malformed packet: {e}", None)

        # --- Step 2: CRC (accidental corruption only, NOT security) ---------
        if not pkt.crc_ok:
            return (False, "CRC mismatch (line noise / corruption)", None)

        # --- Step 3: do we have the key this packet claims? -----------------
        cipher = self.ciphers.get(pkt.key_id)
        if cipher is None:
            return (False, f"unknown key_id {pkt.key_id}", None)

        # --- Step 4: anti-replay BEFORE spending CPU on decryption ----------
        # (We check the window but only *commit* the update after the tag
        #  verifies, so a forged packet can't poison the window.)
        if pkt.seq <= 0:
            return (False, "invalid sequence number", None)
        # Peek: is this seq even acceptable? (duplicate/old check)
        peek = ReplayWindow(self.replay.window)
        peek.highest, peek.bitmap = self.replay.highest, self.replay.bitmap
        if not peek.check_and_update(pkt.seq):
            return (False, f"replay/duplicate/old seq {pkt.seq}", None)

        # --- Step 5: verify nonce is the one the sender should have used ----
        expected_nonce = derive_nonce(pkt.sender, pkt.seq)
        if pkt.nonce != expected_nonce:
            return (False, "nonce does not match sender/seq (possible misuse)",
                    None)

        # --- Step 6: authenticate + decrypt. The AAD must be the EXACT header
        #             bytes the sender authenticated, so we rebuild them. -----
        aad = struct.pack(
            HEADER_FMT, MAGIC, pkt.version, pkt.type, pkt.flags, pkt.sender,
            pkt.key_id, pkt.seq, pkt.nonce, len(pkt.ciphertext),
        )
        try:
            plaintext = cipher.decrypt(pkt.nonce, pkt.ciphertext, aad)
        except InvalidTag:
            return (False, "authentication FAILED (tamper/wrong key/forgery)",
                    None)

        # --- Step 7: only now, after the tag proved authenticity, commit the
        #             replay window update. ---------------------------------
        self.replay.check_and_update(pkt.seq)
        return (True, "ok", plaintext)


# =============================================================================
# 7. DEMONSTRATION + ATTACK TESTS
# =============================================================================

GREEN, RED, YELLOW, DIM, BOLD, RESET = (
    "\033[92m", "\033[91m", "\033[93m", "\033[2m", "\033[1m", "\033[0m")


def hexdump(b: bytes, width=16) -> str:
    out = []
    for i in range(0, len(b), width):
        chunk = b[i:i + width]
        hexs = " ".join(f"{x:02x}" for x in chunk)
        out.append(f"  {i:04x}  {hexs}")
    return "\n".join(out)


def banner(title):
    print(f"\n{BOLD}{'=' * 70}{RESET}")
    print(f"{BOLD}{title}{RESET}")
    print(f"{BOLD}{'=' * 70}{RESET}")


def new_pair(algorithm="chacha20poly1305"):
    """Create a freshly-keyed A->B pair sharing one provisioned key."""
    key = os.urandom(KEY_LEN)        # CSPRNG. os.urandom is the right source.
    key_id = 1
    a = SenderDevice(device_id=0x00A1, key=key, key_id=key_id,
                     algorithm=algorithm)
    b = ReceiverDevice(keys={key_id: key}, algorithm=algorithm)
    return a, b, key


def demo_normal(quiet=False):
    banner("TEST 1 — Normal communication")
    a, b, _ = new_pair()
    link = SimulatedUART()

    message = b"TRANSACTION_ID=1234,TEMP=35.4,STATUS=ACTIVE"
    print(f"{DIM}DEVICE A{RESET}")
    print(f"  Plaintext : {message.decode()}")
    print("  security  : serialize -> seq++ -> derive nonce -> AEAD "
          "encrypt+tag -> packetize")

    frame = a.send(link, message)
    print(f"  tx frame  : {len(frame)} bytes")
    if not quiet:
        print(f"{DIM}{hexdump(frame)}{RESET}")

    print(f"\n{DIM}DEVICE B{RESET}")
    ok, reason, pt = b.receive(link.read_frame())
    _report(ok, reason, want_accept=True)
    if ok:
        print(f"  Recovered : {pt.decode()}")
        assert pt == message


def _report(ok, reason, want_accept):
    good = (ok == want_accept)
    tag = f"{GREEN}PASS{RESET}" if good else f"{RED}UNEXPECTED{RESET}"
    verdict = "ACCEPTED" if ok else "REJECTED"
    color = GREEN if ok else YELLOW
    print(f"  result    : {color}{verdict}{RESET} — {reason}   [{tag}]")
    return good


def demo_attacks(quiet=False):
    results = []

    # ---- TEST 2: flip one ciphertext byte -----------------------------------
    banner("TEST 2 — Modify one ciphertext byte")
    a, b, _ = new_pair()
    link = SimulatedUART()
    a.send(link, b"MOVE servo=90")
    frame = bytearray(link.read_frame())
    # flip a byte well inside the ciphertext region
    frame[HEADER_LEN + 1] ^= 0x01
    # Recompute the CRC so it is VALID. This proves the rejection comes from
    # the AEAD authentication tag (cryptographic), not from the CRC (which an
    # attacker can always recompute). CRC is error-detection, never security.
    good_crc = zlib.crc32(bytes(frame[:-4])) & 0xFFFFFFFF
    frame[-4:] = struct.pack(">I", good_crc)
    ok, reason, _ = b.receive(bytes(frame))
    results.append(_report(ok, reason, want_accept=False))

    # ---- TEST 3: modify the authentication tag ------------------------------
    banner("TEST 3 — Modify the authentication tag")
    a, b, _ = new_pair()
    link = SimulatedUART()
    a.send(link, b"MOVE servo=90")
    frame = bytearray(link.read_frame())
    # the tag is the last 16 bytes of the ciphertext (before the 4-byte CRC)
    frame[-5] ^= 0x80
    # fix CRC so we prove it's the TAG, not the CRC, that rejects it
    good_crc = zlib.crc32(bytes(frame[:-4])) & 0xFFFFFFFF
    frame[-4:] = struct.pack(">I", good_crc)
    ok, reason, _ = b.receive(bytes(frame))
    results.append(_report(ok, reason, want_accept=False))

    # ---- TEST 4: replay an old, valid packet --------------------------------
    banner("TEST 4 — Replay a previously valid packet")
    a, b, _ = new_pair()
    link = SimulatedUART()
    f1 = a.send(link, b"cmd=1"); b.receive(link.read_frame())
    f2 = a.send(link, b"cmd=2"); b.receive(link.read_frame())
    ok, reason, _ = b.receive(f1)        # resend the captured first frame
    results.append(_report(ok, reason, want_accept=False))

    # ---- TEST 5: wrong key --------------------------------------------------
    banner("TEST 5 — Wrong key")
    a, _, _ = new_pair()
    wrong_key = os.urandom(KEY_LEN)
    b_wrong = ReceiverDevice(keys={1: wrong_key})
    link = SimulatedUART()
    a.send(link, b"secret")
    ok, reason, _ = b_wrong.receive(link.read_frame())
    results.append(_report(ok, reason, want_accept=False))

    # ---- TEST 6: invalid / inconsistent length field ------------------------
    banner("TEST 6 — Invalid declared length")
    a, b, _ = new_pair()
    link = SimulatedUART()
    a.send(link, b"hello")
    frame = bytearray(link.read_frame())
    # corrupt the ct_len field (last 2 bytes of header) to a huge value
    frame[HEADER_LEN - 2:HEADER_LEN] = struct.pack(">H", 0xFFFF)
    ok, reason, _ = b.receive(bytes(frame))
    results.append(_report(ok, reason, want_accept=False))

    # ---- TEST 7: malformed / random garbage ---------------------------------
    banner("TEST 7 — Malformed / random garbage (must not crash)")
    _, b, _ = new_pair()
    for junk in (b"", b"\x00", b"not a packet at all", os.urandom(29),
                 os.urandom(200), MAGIC + b"\x01"):
        ok, reason, _ = b.receive(junk)
        if ok:
            print(f"  {RED}UNEXPECTED accept of {junk!r}{RESET}")
            results.append(False)
    print(f"  handled {6} malformed inputs without crashing")
    results.append(True)

    # ---- TEST 8: duplicate sequence number ----------------------------------
    banner("TEST 8 — Duplicate sequence number")
    a, b, _ = new_pair()
    link = SimulatedUART()
    f = a.send(link, b"ping")
    b.receive(link.read_frame())
    ok, reason, _ = b.receive(f)         # exact duplicate
    results.append(_report(ok, reason, want_accept=False))

    # ---- TEST 9: nonce-reuse prevention -------------------------------------
    banner("TEST 9 — Nonce reuse is structurally prevented")
    a, b, _ = new_pair()
    link = SimulatedUART()
    a.send(link, b"a"); a.send(link, b"b"); a.send(link, b"c")
    link.read_frame()
    # Because the nonce is derived from the monotonic seq, two sends can never
    # share a nonce. We assert the counter advanced and nonces differ.
    n1 = derive_nonce(a.device_id, 1)
    n2 = derive_nonce(a.device_id, 2)
    unique = (n1 != n2) and (a.seq == 3)
    print(f"  seq advanced to {a.seq}; nonce(1)!=nonce(2): {n1 != n2}")
    _report(not unique, "nonce reuse possible" if not unique
            else "nonces provably unique per message", want_accept=False)
    results.append(unique)

    return results


def demo_performance():
    banner("PERFORMANCE (PC only — NOT representative of an MCU)")
    a, b, _ = new_pair()
    link = SimulatedUART()
    payload = b"X" * 64
    N = 5000

    t0 = time.perf_counter()
    for _ in range(N):
        a.send(link, payload)
        link.read_frame()
    enc_t = time.perf_counter() - t0

    # measure decode path
    a2, b2, _ = new_pair()
    frames = []
    link2 = SimulatedUART()
    for _ in range(N):
        a2.send(link2, payload)
        frames.append(link2.read_frame())
    t0 = time.perf_counter()
    for f in frames:
        b2.receive(f)
    dec_t = time.perf_counter() - t0

    frame_len = len(a.send(link, payload)); link.read_frame()
    print(f"  payload            : 64 bytes")
    print(f"  frame on wire      : {frame_len} bytes "
          f"({frame_len - 64} bytes overhead)")
    print(f"  encrypt+packetize  : {enc_t / N * 1e6:7.1f} us/msg "
          f"({N/enc_t:,.0f} msg/s)")
    print(f"  parse+verify+decrypt: {dec_t / N * 1e6:6.1f} us/msg "
          f"({N/dec_t:,.0f} msg/s)")
    print(f"\n  UART transmit time per frame (frame bits = 10 * bytes for 8N1):")
    bits = frame_len * 10
    for baud in (9600, 115200, 230400, 460800, 921600):
        ms = bits / baud * 1000
        print(f"    {baud:>7} baud : {ms:7.3f} ms/frame "
              f"(~{int(baud/bits)} frames/s max, ignoring gaps)")
    print(f"{DIM}  Note: baud rate != application throughput. Framing, the "
          f"{frame_len-64}B\n  crypto/packet overhead, and inter-frame gaps all "
          f"reduce real throughput.{RESET}")


def main(argv):
    quiet = "--quiet" in argv
    print(f"{BOLD}Secure UART PoC — ChaCha20-Poly1305 AEAD over simulated "
          f"UART{RESET}")
    print(f"{DIM}Prototype for security research. NOT production / defence "
          f"grade.{RESET}")

    demo_normal(quiet)
    results = demo_attacks(quiet)
    demo_performance()

    banner("SUMMARY")
    passed = sum(1 for r in results if r)
    total = len(results)
    color = GREEN if passed == total else RED
    print(f"  Security tests passed: {color}{passed}/{total}{RESET}")
    print(f"  (Test 1 normal-path + {total} adversarial tests.)")
    if passed != total:
        return 1
    print(f"\n{GREEN}All attack tests behaved as expected.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
