#!/usr/bin/env python3
"""
attack_demo.py — Self-contained security attack demonstration.

Does NOT require device_a.py or device_b.py to be running.
Uses the same crypto/packet/replay code that the real devices use.

Run:
    python3 attack_demo.py
"""

import os
import sys
import struct
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from config import (
    HEADER_FMT, HEADER_LEN, MAGIC, VERSION, FLAG_HAS_CRC,
    DEVICE_A_ID, KEY_ID_DEFAULT, TYPE_DATA,
)
from crypto import AeadCipher, derive_nonce, InvalidTag
from packet import build_packet, parse_packet, PacketError, hex_fmt
from replay import ReplayWindow

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
B = "\033[94m"; D = "\033[2m";  BOLD = "\033[1m"; RST = "\033[0m"


def divider(title: str) -> None:
    print(f"\n{BOLD}{'─' * 50}{RST}")
    print(f"{BOLD}  {title}{RST}")
    print(f"{BOLD}{'─' * 50}{RST}")


def result(accepted: bool, reason: str, want_accept: bool) -> bool:
    correct = accepted == want_accept
    verdict = f"{G}PASS{RST}" if correct else f"{R}UNEXPECTED{RST}"
    status  = f"{G}ACCEPTED{RST}" if accepted else f"{Y}REJECTED{RST}"
    print(f"  Result   : {status}")
    print(f"  Reason   : {reason}")
    print(f"  [{verdict}]")
    return correct


# ---------------------------------------------------------------------------
# Helpers — shared between tests
# ---------------------------------------------------------------------------

def new_env(msg: str = "HELLO DEVICE B"):
    key    = os.urandom(32)
    cipher = AeadCipher(key)
    replay = ReplayWindow()
    seq    = 1
    nonce  = derive_nonce(DEVICE_A_ID, seq)
    ct_len = len(msg.encode()) + 16
    aad    = struct.pack(
        HEADER_FMT, MAGIC, VERSION, TYPE_DATA, FLAG_HAS_CRC,
        DEVICE_A_ID, KEY_ID_DEFAULT, seq, nonce, ct_len,
    )
    ct = cipher.encrypt(nonce, msg.encode(), aad)
    frame = build_packet(
        TYPE_DATA, FLAG_HAS_CRC, DEVICE_A_ID, KEY_ID_DEFAULT,
        seq, nonce, ct, add_crc=True,
    )
    return cipher, replay, frame, key, seq


def receive(frame: bytes, cipher: AeadCipher, replay: ReplayWindow):
    try:
        pkt = parse_packet(frame)
    except PacketError as e:
        return False, f"malformed: {e}"

    if not pkt.crc_ok:
        return False, "CRC mismatch"

    if cipher is None:
        return False, "unknown key_id"

    if not replay.is_acceptable(pkt.seq):
        return False, f"replay/duplicate seq={pkt.seq}"

    exp_nonce = derive_nonce(pkt.sender_id, pkt.seq)
    if pkt.nonce != exp_nonce:
        return False, "nonce mismatch"

    aad = struct.pack(
        HEADER_FMT, MAGIC, pkt.version, pkt.type, pkt.flags,
        pkt.sender_id, pkt.key_id, pkt.seq, pkt.nonce, len(pkt.ciphertext),
    )
    try:
        pt = cipher.decrypt(pkt.nonce, pkt.ciphertext, aad)
    except InvalidTag:
        return False, "AUTHENTICATION FAILED"

    replay.accept(pkt.seq)
    return True, pt.decode()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_normal():
    divider("TEST 1 — Normal communication")
    cipher, replay, frame, _, _ = new_env("HELLO DEVICE B")
    print(f"  Sending  : HELLO DEVICE B")
    print(f"  Packet   : {frame[:20].hex()}...")
    ok, reason = receive(frame, cipher, replay)
    return result(ok, reason, want_accept=True)


def test_flip_ciphertext():
    divider("TEST 2 — Flip one ciphertext byte (attacker tampers payload)")
    cipher, replay, frame, _, _ = new_env("MOVE servo=90")
    frame = bytearray(frame)
    frame[HEADER_LEN + 2] ^= 0xFF
    # fix CRC so only the AEAD tag catches it
    crc = zlib.crc32(bytes(frame[:-4])) & 0xFFFFFFFF
    frame[-4:] = struct.pack(">I", crc)
    print(f"  Action   : Flipped ciphertext byte #{HEADER_LEN + 2}, CRC recomputed")
    print(f"  (CRC is NOT security — the AEAD tag is)")
    ok, reason = receive(bytes(frame), cipher, replay)
    return result(ok, reason, want_accept=False)


def test_modify_tag():
    divider("TEST 3 — Modify the authentication tag")
    cipher, replay, frame, _, _ = new_env("FIRE engine=1")
    frame = bytearray(frame)
    frame[-5] ^= 0xAA          # tag is last 16 bytes of ciphertext, before CRC
    crc = zlib.crc32(bytes(frame[:-4])) & 0xFFFFFFFF
    frame[-4:] = struct.pack(">I", crc)
    print(f"  Action   : Flipped auth tag byte, CRC recomputed")
    ok, reason = receive(bytes(frame), cipher, replay)
    return result(ok, reason, want_accept=False)


def test_replay():
    divider("TEST 4 — Replay a previously accepted packet")
    cipher, replay, frame1, _, _ = new_env("cmd=1")
    _, _, frame2, _, _ = new_env("cmd=2")
    cipher2 = AeadCipher(os.urandom(32))
    # build a second message with same cipher+replay window
    key = os.urandom(32)
    c = AeadCipher(key); r = ReplayWindow()
    seq1 = 1; nonce1 = derive_nonce(DEVICE_A_ID, seq1)
    ct_len = len(b"cmd=1") + 16
    aad1 = struct.pack(HEADER_FMT, MAGIC, VERSION, TYPE_DATA, FLAG_HAS_CRC,
                       DEVICE_A_ID, KEY_ID_DEFAULT, seq1, nonce1, ct_len)
    ct1 = c.encrypt(nonce1, b"cmd=1", aad1)
    f1  = build_packet(TYPE_DATA, FLAG_HAS_CRC, DEVICE_A_ID, KEY_ID_DEFAULT,
                       seq1, nonce1, ct1, add_crc=True)

    seq2 = 2; nonce2 = derive_nonce(DEVICE_A_ID, seq2)
    ct_len2 = len(b"cmd=2") + 16
    aad2 = struct.pack(HEADER_FMT, MAGIC, VERSION, TYPE_DATA, FLAG_HAS_CRC,
                       DEVICE_A_ID, KEY_ID_DEFAULT, seq2, nonce2, ct_len2)
    ct2 = c.encrypt(nonce2, b"cmd=2", aad2)
    f2  = build_packet(TYPE_DATA, FLAG_HAS_CRC, DEVICE_A_ID, KEY_ID_DEFAULT,
                       seq2, nonce2, ct2, add_crc=True)

    r.accept(1); r.accept(2)   # both delivered
    print(f"  Delivered: seq=1 and seq=2")
    print(f"  Attack   : replay seq=1")
    ok, reason = receive(f1, c, r)
    return result(ok, reason, want_accept=False)


def test_wrong_key():
    divider("TEST 5 — Wrong key on Device B")
    cipher_a, replay, frame, _, _ = new_env("SECRET COMMAND")
    wrong_cipher = AeadCipher(os.urandom(32))
    print(f"  Action   : Device B uses a different key")
    ok, reason = receive(frame, wrong_cipher, replay)
    return result(ok, reason, want_accept=False)


def test_malformed():
    divider("TEST 6 — Malformed / garbage packets (no crash)")
    cipher, replay, _, _, _ = new_env()
    garbage = [
        b"",
        b"\x00",
        b"not a packet at all",
        os.urandom(15),
        os.urandom(200),
        MAGIC + b"\x01",
        b"\xFF" * 50,
    ]
    all_pass = True
    for i, g in enumerate(garbage):
        try:
            ok, reason = receive(g, cipher, replay)
            tag = f"{G}PASS{RST}" if not ok else f"{R}UNEXPECTED ACCEPT{RST}"
        except Exception as e:
            ok, reason = False, str(e)
            tag = f"{R}CRASHED: {e}{RST}"
            all_pass = False
        print(f"  Input {i+1:2d}  : {g[:16].hex() or '(empty)':20s}  → {tag}")
    return all_pass


def test_duplicate_seq():
    divider("TEST 7 — Duplicate sequence number")
    key = os.urandom(32); c = AeadCipher(key); r = ReplayWindow()
    def make(seq, msg):
        n = derive_nonce(DEVICE_A_ID, seq)
        ct_l = len(msg) + 16
        aad = struct.pack(HEADER_FMT, MAGIC, VERSION, TYPE_DATA, FLAG_HAS_CRC,
                          DEVICE_A_ID, KEY_ID_DEFAULT, seq, n, ct_l)
        ct = c.encrypt(n, msg, aad)
        return build_packet(TYPE_DATA, FLAG_HAS_CRC, DEVICE_A_ID, KEY_ID_DEFAULT,
                            seq, n, ct, add_crc=True)
    f = make(1, b"ping")
    receive(f, c, r)           # first delivery — should succeed
    print(f"  First delivery of seq=1: accepted (expected)")
    print(f"  Second delivery of seq=1:")
    ok, reason = receive(f, c, r)
    return result(ok, reason, want_accept=False)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print(f"\n{BOLD}{'=' * 50}{RST}")
    print(f"{BOLD}  SECURE UART — ATTACK DEMONSTRATION{RST}")
    print(f"{BOLD}{'=' * 50}{RST}")
    print(f"{D}  Same crypto/packet/replay code as the real devices.{RST}")
    print(f"{D}  Prototype — not production grade.{RST}")

    tests = [
        test_normal,
        test_flip_ciphertext,
        test_modify_tag,
        test_replay,
        test_wrong_key,
        test_malformed,
        test_duplicate_seq,
    ]

    results = []
    for t in tests:
        try:
            results.append(t())
        except Exception as e:
            print(f"\n{R}Test raised unexpected exception: {e}{RST}")
            results.append(False)

    passed = sum(results)
    total  = len(results)

    print(f"\n{BOLD}{'=' * 50}{RST}")
    print(f"{BOLD}  RESULTS: {G if passed == total else R}{passed}/{total} passed{RST}")
    print(f"{BOLD}{'=' * 50}{RST}\n")

    if passed == total:
        print(f"{G}All attacks handled correctly.{RST}\n")
    else:
        print(f"{R}Some tests failed — review above.{RST}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
