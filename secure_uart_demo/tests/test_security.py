"""
End-to-end security tests — exercises the full send/receive path.
These tests prove each security control fires independently.
"""

import sys, os, struct, zlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from config import HEADER_FMT, HEADER_LEN, MAGIC, VERSION, FLAG_HAS_CRC, \
                   DEVICE_A_ID, KEY_ID_DEFAULT, TYPE_DATA
from crypto import AeadCipher, derive_nonce, InvalidTag
from packet import build_packet, parse_packet, PacketError
from replay import ReplayWindow


# --- shared helpers ----------------------------------------------------------

def make_session():
    key    = os.urandom(32)
    cipher = AeadCipher(key)
    replay = ReplayWindow()
    return key, cipher, replay


def make_frame(cipher, seq, msg=b"test msg"):
    nonce  = derive_nonce(DEVICE_A_ID, seq)
    ct_len = len(msg) + 16
    aad    = struct.pack(HEADER_FMT, MAGIC, VERSION, TYPE_DATA, FLAG_HAS_CRC,
                         DEVICE_A_ID, KEY_ID_DEFAULT, seq, nonce, ct_len)
    ct     = cipher.encrypt(nonce, msg, aad)
    return build_packet(TYPE_DATA, FLAG_HAS_CRC, DEVICE_A_ID, KEY_ID_DEFAULT,
                        seq, nonce, ct, add_crc=True)


def receive(frame, cipher, replay):
    try:
        pkt = parse_packet(frame)
    except PacketError as e:
        return False, f"malformed: {e}"
    if not pkt.crc_ok:
        return False, "crc"
    if not replay.is_acceptable(pkt.seq):
        return False, "replay"
    exp = derive_nonce(pkt.sender_id, pkt.seq)
    if pkt.nonce != exp:
        return False, "nonce"
    aad = struct.pack(HEADER_FMT, MAGIC, pkt.version, pkt.type, pkt.flags,
                      pkt.sender_id, pkt.key_id, pkt.seq, pkt.nonce,
                      len(pkt.ciphertext))
    try:
        pt = cipher.decrypt(pkt.nonce, pkt.ciphertext, aad)
    except InvalidTag:
        return False, "auth_failed"
    replay.accept(pkt.seq)
    return True, pt.decode()


# --- tests -------------------------------------------------------------------

def test_normal_delivery():
    _, c, r = make_session()
    ok, msg = receive(make_frame(c, 1), c, r)
    assert ok is True
    assert msg == "test msg"


def test_tamper_ciphertext_rejected():
    _, c, r = make_session()
    frame = bytearray(make_frame(c, 1))
    frame[HEADER_LEN + 2] ^= 0xFF
    crc = zlib.crc32(bytes(frame[:-4])) & 0xFFFFFFFF
    frame[-4:] = struct.pack(">I", crc)
    ok, reason = receive(bytes(frame), c, r)
    assert ok is False
    assert reason == "auth_failed"


def test_tamper_tag_rejected():
    _, c, r = make_session()
    frame = bytearray(make_frame(c, 1))
    frame[-5] ^= 0xAA
    crc = zlib.crc32(bytes(frame[:-4])) & 0xFFFFFFFF
    frame[-4:] = struct.pack(">I", crc)
    ok, reason = receive(bytes(frame), c, r)
    assert ok is False
    assert reason == "auth_failed"


def test_replay_rejected():
    _, c, r = make_session()
    f = make_frame(c, 1)
    ok1, _ = receive(f, c, r)
    ok2, _ = receive(f, c, r)
    assert ok1 is True
    assert ok2 is False


def test_wrong_key_rejected():
    _, c_a, r = make_session()
    _, c_b, _ = make_session()
    frame = make_frame(c_a, 1)
    ok, reason = receive(frame, c_b, r)
    assert ok is False
    assert reason == "auth_failed"


def test_sequence_advances():
    _, c, r = make_session()
    for seq in range(1, 6):
        ok, _ = receive(make_frame(c, seq), c, r)
        assert ok is True, f"seq {seq} should be accepted"


def test_old_seq_outside_window_rejected():
    _, c, r = make_session()
    for seq in range(1, 70):
        receive(make_frame(c, seq), c, r)
    ok, reason = receive(make_frame(c, 1), c, r)
    assert ok is False


def test_malformed_never_crashes():
    _, c, r = make_session()
    junk = [b"", b"\x00", b"garbage", os.urandom(50), b"\xFF" * 100]
    for j in junk:
        ok, reason = receive(j, c, r)
        assert ok is False


def test_replay_window_only_committed_after_auth():
    _, c_a, r = make_session()
    _, c_wrong, _ = make_session()
    f = make_frame(c_a, 1)
    # wrong key attempt — should NOT consume seq=1 from the window
    ok1, _ = receive(f, c_wrong, r)
    assert ok1 is False
    # correct key attempt — seq=1 still available
    ok2, _ = receive(f, c_a, r)
    assert ok2 is True
