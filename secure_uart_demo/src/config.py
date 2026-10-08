import os
import struct

MAGIC   = b"\x53\x55"
VERSION = 0x01

NONCE_LEN = 12
TAG_LEN   = 16
KEY_LEN   = 32

TYPE_DATA      = 0x01
TYPE_COMMAND   = 0x02
TYPE_STATUS    = 0x03
TYPE_HEARTBEAT = 0x04

MSG_TYPE_NAMES = {
    TYPE_DATA:      "DATA",
    TYPE_COMMAND:   "COMMAND",
    TYPE_STATUS:    "STATUS",
    TYPE_HEARTBEAT: "HEARTBEAT",
}

FLAG_HAS_CRC = 0x01

# Header layout (big-endian, 30 bytes total):
#   magic(2) version(1) type(1) flags(1) sender_id(2) key_id(1)
#   seq(8)   nonce(12)  ct_len(2)
HEADER_FMT = ">2sBBBHBQ12sH"
HEADER_LEN = struct.calcsize(HEADER_FMT)   # = 30

SOCKET_HOST = "127.0.0.1"
SOCKET_PORT = 9999

DEVICE_A_ID = 0x00A1
DEVICE_B_ID = 0x00B1

KEY_ID_DEFAULT = 0x01

_ROOT    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY_FILE = os.path.join(_ROOT, ".dev_key.bin")
SEQ_FILE = os.path.join(_ROOT, ".seq_a.dat")


def load_dev_key() -> bytes | None:
    if not os.path.exists(KEY_FILE):
        return None
    with open(KEY_FILE, "rb") as f:
        return f.read()


def save_dev_key(key: bytes) -> None:
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    os.chmod(KEY_FILE, 0o600)


def load_seq() -> int:
    if not os.path.exists(SEQ_FILE):
        return 0
    with open(SEQ_FILE, "rb") as f:
        data = f.read()
    return int.from_bytes(data, "big") if len(data) == 8 else 0


def save_seq(seq: int) -> None:
    with open(SEQ_FILE, "wb") as f:
        f.write(seq.to_bytes(8, "big"))
