import struct
import zlib
from dataclasses import dataclass

from config import (
    MAGIC, VERSION, HEADER_FMT, HEADER_LEN,
    TAG_LEN, FLAG_HAS_CRC,
)

__all__ = ["Packet", "PacketError", "build_packet", "parse_packet", "hex_fmt"]


class PacketError(Exception):
    pass


@dataclass
class Packet:
    version:    int
    type:       int
    flags:      int
    sender_id:  int
    key_id:     int
    seq:        int
    nonce:      bytes
    ciphertext: bytes   # includes the 16-byte authentication tag
    crc_ok:     bool = True


def build_packet(
    msg_type: int,
    flags: int,
    sender_id: int,
    key_id: int,
    seq: int,
    nonce: bytes,
    ciphertext: bytes,
    add_crc: bool = True,
) -> bytes:
    if add_crc:
        flags |= FLAG_HAS_CRC

    header = struct.pack(
        HEADER_FMT,
        MAGIC, VERSION, msg_type, flags,
        sender_id, key_id, seq, nonce,
        len(ciphertext),
    )
    frame = header + ciphertext
    if flags & FLAG_HAS_CRC:
        crc = zlib.crc32(frame) & 0xFFFFFFFF
        frame += struct.pack(">I", crc)
    return frame


def parse_packet(frame: bytes) -> Packet:
    if len(frame) < HEADER_LEN + TAG_LEN:
        raise PacketError(f"frame too short: {len(frame)} bytes")

    magic, version, msg_type, flags, sender_id, key_id, seq, nonce, ct_len = \
        struct.unpack(HEADER_FMT, frame[:HEADER_LEN])

    if magic != MAGIC:
        raise PacketError("bad magic bytes — not a valid frame")
    if version != VERSION:
        raise PacketError(f"unsupported protocol version: {version}")
    if ct_len < TAG_LEN:
        raise PacketError("declared ciphertext length shorter than tag")

    has_crc     = bool(flags & FLAG_HAS_CRC)
    ct_end      = HEADER_LEN + ct_len
    expect_len  = ct_end + (4 if has_crc else 0)

    if len(frame) != expect_len:
        raise PacketError(
            f"length mismatch: expected {expect_len}, got {len(frame)}"
        )

    ciphertext = frame[HEADER_LEN:ct_end]
    crc_ok = True
    if has_crc:
        got_crc  = struct.unpack(">I", frame[ct_end:ct_end + 4])[0]
        calc_crc = zlib.crc32(frame[:ct_end]) & 0xFFFFFFFF
        crc_ok   = (got_crc == calc_crc)

    return Packet(version, msg_type, flags, sender_id, key_id,
                  seq, nonce, ciphertext, crc_ok)


def hex_fmt(data: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        lines.append("  " + " ".join(f"{b:02X}" for b in chunk))
    return "\n".join(lines)
