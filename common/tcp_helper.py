"""Minimal TCP framing helper: 2-byte big-endian length || payload. Provides NO security."""
import socket, struct

MAX = 0xFFFF

def send_msg(sock, data: bytes):
    if len(data) > MAX:
        raise ValueError(f"frame too large ({len(data)} > {MAX})")
    sock.sendall(struct.pack(">H", len(data)) + data)

def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed connection")
        buf += chunk
    return buf

def recv_msg(sock) -> bytes:
    (n,) = struct.unpack(">H", _recv_exact(sock, 2))
    return _recv_exact(sock, n)

def send_fields(sock, fields):
    send_msg(sock, len(fields).to_bytes(2, "big"))
    for f in fields:
        send_msg(sock, f)

def recv_fields(sock):
    n = int.from_bytes(recv_msg(sock), "big")
    return [recv_msg(sock) for _ in range(n)]

def listen(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port)); s.listen(1)
    return s

def connect(host, port):
    return socket.create_connection((host, port), timeout=30)
