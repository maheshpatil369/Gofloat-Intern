#!/usr/bin/env python3
"""
DEVICE A — Secure Sender

Run in Terminal 1:
    python3 src/device_a.py
    python3 src/device_a.py --port /dev/ttyUSB0 --baudrate 115200   (real UART)
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import struct
from config import (
    HEADER_FMT, HEADER_LEN, MAGIC, VERSION, FLAG_HAS_CRC,
    SOCKET_HOST, SOCKET_PORT,
    DEVICE_A_ID, KEY_ID_DEFAULT, TYPE_DATA,
    load_dev_key, load_seq, save_seq,
)
from crypto import AeadCipher, derive_nonce
from packet import build_packet, hex_fmt
from transport import SocketClientTransport, UartTransport, TransportError

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
B = "\033[94m"; D = "\033[2m";  BOLD = "\033[1m"; RST = "\033[0m"

BANNER = f"""
{BOLD}{'=' * 44}
  DEVICE A  —  SECURE SENDER
{'=' * 44}{RST}"""


def banner_line(label: str, value: str) -> None:
    print(f"  {D}{label:<18}{RST}{value}")


def section(title: str) -> None:
    print(f"\n{BOLD}[{title}]{RST}")


def send_message(
    cipher: AeadCipher,
    transport,
    message: str,
    seq: int,
) -> bytes:
    payload = message.encode("utf-8")
    nonce   = derive_nonce(DEVICE_A_ID, seq)

    # Build the header first so it can be used as AAD
    ct_placeholder = len(payload) + 16
    aad = struct.pack(
        HEADER_FMT,
        MAGIC, VERSION, TYPE_DATA, FLAG_HAS_CRC,
        DEVICE_A_ID, KEY_ID_DEFAULT, seq, nonce, ct_placeholder,
    )

    ciphertext = cipher.encrypt(nonce, payload, aad)

    frame = build_packet(
        msg_type  = TYPE_DATA,
        flags     = FLAG_HAS_CRC,
        sender_id = DEVICE_A_ID,
        key_id    = KEY_ID_DEFAULT,
        seq       = seq,
        nonce     = nonce,
        ciphertext= ciphertext,
        add_crc   = True,
    )

    section("ENCRYPTING")
    print(f"  {'Plaintext':<18}: {message}")
    print(f"  {'Nonce':<18}: {nonce.hex()}")
    print(f"  {'Sequence':<18}: {seq}")
    print(f"\n  Ciphertext (payload, no tag):")
    print(hex_fmt(ciphertext[:-16]))
    print(f"\n  Authentication tag:")
    print(hex_fmt(ciphertext[-16:]))

    section("PACKET")
    print(f"  Total size : {len(frame)} bytes "
          f"({HEADER_LEN} header + {len(ciphertext)} ct+tag + 4 crc)")
    print(f"\n  Full packet (HEX):")
    print(hex_fmt(frame))

    section("TRANSMITTING")
    transport.send_frame(frame)
    print(f"  {G}✓ Packet transmitted ({len(frame)} bytes){RST}")

    return frame


def run(args) -> None:
    print(BANNER)

    key = load_dev_key()
    if key is None:
        print(f"\n{R}ERROR: Key file not found.{RST}")
        print("  Start Device B first — it generates the shared key.")
        sys.exit(1)

    cipher = AeadCipher(key)
    seq    = load_seq()

    if args.port:
        transport = UartTransport(args.port, args.baudrate)
        transport_name = f"REAL UART {args.port} @ {args.baudrate} baud"
        try:
            transport.open()
        except Exception as e:
            print(f"{R}Cannot open UART: {e}{RST}")
            sys.exit(1)
    else:
        transport = SocketClientTransport(SOCKET_HOST, SOCKET_PORT)
        transport_name = f"SIMULATED UART (socket://{SOCKET_HOST}:{SOCKET_PORT})"
        try:
            transport.connect()
        except ConnectionRefusedError:
            print(f"\n{R}Cannot connect. Is Device B running?{RST}")
            print(f"  Start it with:  python3 src/device_b.py")
            sys.exit(1)

    print()
    banner_line("Transport",  transport_name)
    banner_line("Algorithm",  cipher.display_name)
    banner_line("Device ID",  f"0x{DEVICE_A_ID:04X}")
    banner_line("Key ID",     f"0x{KEY_ID_DEFAULT:02X}")
    print()

    try:
        while True:
            try:
                message = input(f"{BOLD}Enter message{RST} (or 'quit'): ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break

            if not message or message.lower() == "quit":
                break

            seq += 1
            save_seq(seq)

            send_message(cipher, transport, message, seq)
            print()

    finally:
        transport.close()
        print(f"\n{D}Device A closed.{RST}\n")


def main() -> None:
    p = argparse.ArgumentParser(description="Device A — Secure Sender")
    p.add_argument("--port",     default=None,  help="Serial port (e.g. /dev/ttyUSB0)")
    p.add_argument("--baudrate", default=115200, type=int, help="Baud rate (default 115200)")
    run(p.parse_args())


if __name__ == "__main__":
    main()
