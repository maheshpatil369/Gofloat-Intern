#!/usr/bin/env python3
"""
DEVICE B — Secure Receiver

Run in Terminal 2 (start this FIRST):
    python3 src/device_b.py
    python3 src/device_b.py --port /dev/ttyUSB0 --baudrate 115200   (real UART)
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import struct
from config import (
    HEADER_FMT, HEADER_LEN, MAGIC, VERSION, FLAG_HAS_CRC,
    SOCKET_HOST, SOCKET_PORT,
    DEVICE_A_ID, KEY_ID_DEFAULT,
    MSG_TYPE_NAMES,
    load_dev_key, save_dev_key,
)
from crypto import AeadCipher, derive_nonce, InvalidTag
from packet import parse_packet, PacketError, hex_fmt
from replay import ReplayWindow
from transport import SocketServerTransport, UartTransport

import os as _os

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
B = "\033[94m"; D = "\033[2m";  BOLD = "\033[1m"; RST = "\033[0m"

BANNER = f"""
{BOLD}{'=' * 44}
  DEVICE B  —  SECURE RECEIVER
{'=' * 44}{RST}"""


def section(title: str) -> None:
    print(f"\n{BOLD}[{title}]{RST}")


def ok(label: str) -> None:
    print(f"  {G}✓{RST} {label}")


def fail(label: str) -> None:
    print(f"  {R}✗{RST} {label}")


def process_frame(frame: bytes, ciphers: dict, replay: ReplayWindow) -> None:
    section("RECEIVED")
    print(f"  Frame size : {len(frame)} bytes")
    print(f"\n  Raw HEX:")
    print(hex_fmt(frame))

    # --- 1. structural parse -------------------------------------------------
    section("PACKET VALIDATION")
    try:
        pkt = parse_packet(frame)
    except PacketError as e:
        fail(f"Header/structure invalid: {e}")
        print(f"\n  {R}PACKET REJECTED — malformed{RST}")
        return

    ok("Magic bytes valid")
    ok(f"Protocol version: {pkt.version}")
    ok(f"Length consistent: {len(pkt.ciphertext)} bytes ciphertext")

    # --- 2. CRC (line noise, not security) -----------------------------------
    if not pkt.crc_ok:
        fail("CRC mismatch (accidental corruption)")
        print(f"\n  {R}PACKET REJECTED — CRC error{RST}")
        return
    ok("CRC valid (no accidental corruption)")

    # --- 3. key lookup -------------------------------------------------------
    cipher = ciphers.get(pkt.key_id)
    if cipher is None:
        fail(f"Unknown key ID: 0x{pkt.key_id:02X}")
        print(f"\n  {R}PACKET REJECTED — unknown key{RST}")
        return
    ok(f"Key ID 0x{pkt.key_id:02X} found")

    # --- 4. anti-replay (pre-check, don't commit yet) -------------------------
    if not replay.is_acceptable(pkt.seq):
        fail(f"Sequence {pkt.seq} rejected (replay / duplicate / too old)")
        print(f"\n  {Y}PACKET REJECTED — REPLAY ATTACK DETECTED{RST}")
        return
    ok(f"Sequence {pkt.seq} acceptable (anti-replay pre-check)")

    # --- 5. nonce verification -----------------------------------------------
    expected_nonce = derive_nonce(pkt.sender_id, pkt.seq)
    if pkt.nonce != expected_nonce:
        fail("Nonce does not match sender/sequence")
        print(f"\n  {R}PACKET REJECTED — nonce mismatch{RST}")
        return
    ok(f"Nonce valid (sender=0x{pkt.sender_id:04X}, seq={pkt.seq})")

    # --- 6. authenticate + decrypt -------------------------------------------
    aad = struct.pack(
        HEADER_FMT,
        MAGIC, pkt.version, pkt.type, pkt.flags,
        pkt.sender_id, pkt.key_id, pkt.seq, pkt.nonce,
        len(pkt.ciphertext),
    )

    section("AUTHENTICATION + DECRYPTION")
    try:
        plaintext = cipher.decrypt(pkt.nonce, pkt.ciphertext, aad)
    except InvalidTag:
        fail("Authentication tag FAILED — packet tampered, wrong key, or forged")
        print(f"\n  {R}PACKET REJECTED — AUTHENTICATION FAILED{RST}")
        return

    ok("Authentication tag verified")

    # --- 7. commit replay window only after auth succeeds --------------------
    replay.accept(pkt.seq)
    ok("Decryption successful")
    ok("Replay window updated")

    section("MESSAGE")
    msg_type = MSG_TYPE_NAMES.get(pkt.type, f"0x{pkt.type:02X}")
    print(f"  Sender   : 0x{pkt.sender_id:04X}")
    print(f"  Type     : {msg_type}")
    print(f"  Sequence : {pkt.seq}")
    print()
    print(f"  {BOLD}{G}{plaintext.decode('utf-8', errors='replace')}{RST}")
    print(f"\n{'=' * 44}")


def run(args) -> None:
    print(BANNER)

    key = load_dev_key()
    if key is None:
        import os as _os2
        key = _os2.urandom(32)
        save_dev_key(key)
        print(f"\n{G}New key generated and saved to .dev_key.bin{RST}")
        print(f"{D}(Share this file with Device A before running it){RST}")
    else:
        print(f"\n{D}Loaded key from .dev_key.bin{RST}")

    ciphers = {KEY_ID_DEFAULT: AeadCipher(key)}
    replay  = ReplayWindow()

    if args.port:
        transport = UartTransport(args.port, args.baudrate)
        transport_name = f"REAL UART {args.port} @ {args.baudrate} baud"
        try:
            transport.open()
        except Exception as e:
            print(f"{R}Cannot open UART: {e}{RST}")
            sys.exit(1)

        print(f"\n  Transport : {transport_name}")
        print(f"  Algorithm : {ciphers[KEY_ID_DEFAULT].display_name}")
        print(f"\n{BOLD}Waiting for packets...{RST}\n")
        try:
            while True:
                frame = transport.recv_frame()
                if frame:
                    process_frame(frame, ciphers, replay)
                    print(f"\n{BOLD}Waiting for next packet...{RST}\n")
        except KeyboardInterrupt:
            pass
        finally:
            transport.close()
    else:
        server = SocketServerTransport(SOCKET_HOST, SOCKET_PORT)
        server.listen()
        transport_name = f"SIMULATED UART (socket://{SOCKET_HOST}:{SOCKET_PORT})"

        print(f"\n  Transport : {transport_name}")
        print(f"  Algorithm : {ciphers[KEY_ID_DEFAULT].display_name}")
        print(f"\n{BOLD}Listening on {SOCKET_HOST}:{SOCKET_PORT}{RST}")
        print(f"{D}Start Device A in another terminal:{RST}")
        print(f"    python3 src/device_a.py\n")

        try:
            while True:
                print(f"{BOLD}Waiting for connection...{RST}")
                addr = server.accept()
                print(f"{G}Device A connected from {addr}{RST}\n")

                while True:
                    frame = server.recv_frame()
                    if frame is None:
                        print(f"\n{Y}Device A disconnected.{RST}\n")
                        break
                    process_frame(frame, ciphers, replay)
                    print(f"\n{BOLD}Waiting for next packet...{RST}\n")

        except KeyboardInterrupt:
            pass
        finally:
            server.close()

    print(f"\n{D}Device B closed.{RST}\n")


def main() -> None:
    p = argparse.ArgumentParser(description="Device B — Secure Receiver")
    p.add_argument("--port",     default=None,  help="Serial port (e.g. /dev/ttyUSB0)")
    p.add_argument("--baudrate", default=115200, type=int, help="Baud rate (default 115200)")
    run(p.parse_args())


if __name__ == "__main__":
    main()
