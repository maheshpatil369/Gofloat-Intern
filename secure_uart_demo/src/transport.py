"""
Transport abstraction.

The security protocol is completely independent from the transport.
Swap SimulatedUART <-> RealUART without touching crypto, packet, or
device logic.

Framing over socket/serial:
  [4 bytes big-endian uint32 = packet length] [packet bytes]

This gives the receiver a reliable frame boundary, mirroring what
MAGIC + CT_LEN does in a raw UART byte stream.
"""

import socket
import struct
import sys

__all__ = [
    "TransportError",
    "SocketServerTransport",
    "SocketClientTransport",
    "UartTransport",
]

_FRAME_PREFIX = ">I"   # 4-byte big-endian length prefix


class TransportError(Exception):
    pass


# ---------------------------------------------------------------------------
# Simulated UART — two processes connected via TCP loopback
# ---------------------------------------------------------------------------

class SocketServerTransport:
    """Device B side: listens and accepts incoming connections."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._server  = None
        self._conn    = None

    def listen(self) -> None:
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((self.host, self.port))
        self._server.listen(1)

    def accept(self) -> str:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
        self._conn, addr = self._server.accept()
        return f"{addr[0]}:{addr[1]}"

    def recv_frame(self) -> bytes | None:
        try:
            raw = self._recv_exact(4)
            if not raw:
                return None
            length = struct.unpack(_FRAME_PREFIX, raw)[0]
            if length == 0 or length > 65535:
                return None
            return self._recv_exact(length)
        except (ConnectionResetError, BrokenPipeError, OSError):
            return None

    def _recv_exact(self, n: int) -> bytes | None:
        buf = b""
        while len(buf) < n:
            chunk = self._conn.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def close(self) -> None:
        if self._conn:
            self._conn.close()
        if self._server:
            self._server.close()


class SocketClientTransport:
    """Device A side: connects to the server."""

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self._sock = None

    def connect(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.connect((self.host, self.port))

    def send_frame(self, data: bytes) -> None:
        prefix = struct.pack(_FRAME_PREFIX, len(data))
        self._sock.sendall(prefix + data)

    def close(self) -> None:
        if self._sock:
            self._sock.close()


# ---------------------------------------------------------------------------
# Real UART — pyserial (optional, import guarded)
# ---------------------------------------------------------------------------

class UartTransport:
    """
    Real UART transport via pyserial.

    Usage:
        t = UartTransport("/dev/ttyUSB0", 115200)
        t.open()
        t.send_frame(data)
        frame = t.recv_frame()
        t.close()
    """

    def __init__(self, port: str, baudrate: int = 115200):
        try:
            import serial as _serial
            self._serial_mod = _serial
        except ImportError:
            raise TransportError(
                "pyserial not installed. Run: pip install pyserial"
            )
        self.port     = port
        self.baudrate = baudrate
        self._ser     = None

    def open(self) -> None:
        self._ser = self._serial_mod.Serial(
            self.port, self.baudrate,
            bytesize=8, parity="N", stopbits=1,
            timeout=5,
        )

    def send_frame(self, data: bytes) -> None:
        prefix = struct.pack(_FRAME_PREFIX, len(data))
        self._ser.write(prefix + data)
        self._ser.flush()

    def recv_frame(self) -> bytes | None:
        raw = self._ser.read(4)
        if len(raw) < 4:
            return None
        length = struct.unpack(_FRAME_PREFIX, raw)[0]
        if length == 0 or length > 65535:
            return None
        return self._ser.read(length) or None

    def close(self) -> None:
        if self._ser and self._ser.is_open:
            self._ser.close()
