import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import struct, zlib
import pytest
from config import MAGIC, HEADER_LEN, HEADER_FMT, FLAG_HAS_CRC, VERSION
from packet import build_packet, parse_packet, PacketError


def make_frame(msg_type=0x01, flags=FLAG_HAS_CRC, sender=0x00A1,
               key_id=0x01, seq=1, nonce=None, ct=None, add_crc=True):
    if nonce is None:
        nonce = b"\x00" * 12
    if ct is None:
        ct = b"\xAB" * 29   # 13 payload + 16 tag
    return build_packet(msg_type, flags, sender, key_id, seq, nonce, ct, add_crc)


def test_round_trip_fields():
    nonce  = os.urandom(12)
    ct     = os.urandom(29)
    frame  = make_frame(seq=7, nonce=nonce, ct=ct)
    pkt    = parse_packet(frame)
    assert pkt.seq       == 7
    assert pkt.nonce     == nonce
    assert pkt.ciphertext == ct
    assert pkt.crc_ok    is True
    assert pkt.sender_id == 0x00A1


def test_too_short_raises():
    with pytest.raises(PacketError):
        parse_packet(b"\x53\x55" + b"\x00" * 10)


def test_wrong_magic_raises():
    frame = make_frame()
    bad   = b"\xFF\xFF" + frame[2:]
    with pytest.raises(PacketError, match="magic"):
        parse_packet(bad)


def test_wrong_version_raises():
    frame = bytearray(make_frame())
    frame[2] = 0xFF
    with pytest.raises(PacketError, match="version"):
        parse_packet(bytes(frame))


def test_length_mismatch_raises():
    frame = bytearray(make_frame())
    frame[HEADER_LEN - 2:HEADER_LEN] = struct.pack(">H", 0xFFFF)
    with pytest.raises(PacketError, match="length"):
        parse_packet(bytes(frame))


def test_crc_detected():
    frame = bytearray(make_frame())
    frame[-1] ^= 0x01
    pkt = parse_packet(bytes(frame))
    assert pkt.crc_ok is False


def test_no_crc_option():
    frame = make_frame(flags=0x00, add_crc=False)
    pkt   = parse_packet(frame)
    assert pkt.crc_ok is True   # no CRC field = ok by default
    assert pkt.flags  == 0x00


def test_empty_frame():
    with pytest.raises(PacketError):
        parse_packet(b"")


def test_random_garbage():
    import os as _os
    for _ in range(20):
        with pytest.raises(PacketError):
            parse_packet(_os.urandom(50))
