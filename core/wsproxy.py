#!/usr/bin/env python3
"""
Ragnar SSH WebSocket proxy (stdlib only).

Listens on 127.0.0.1:10005 and bridges WebSocket binary frames to the local
SSH backend (Dropbear 127.0.0.1:109, falling back to OpenSSH 127.0.0.1:22).
HAProxy terminates TLS in front of it, so the same backend serves both
WS (port 80) and WSS (port 443) on path /ragnar-sshws.

Clients: HTTP Custom, NapsternetV, ZIVPN Tunnel, HA Tunnel Plus, etc.
"""
import base64
import hashlib
import os
import select
import socket
import struct
import sys
import threading

LISTEN = ("127.0.0.1", int(os.environ.get("RAGNAR_WSPORT", "10005")))
BACKENDS = [("127.0.0.1", 109), ("127.0.0.1", 22)]  # dropbear, then openssh
GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME = 1 << 20


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf


def read_http_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed during handshake")
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    headers = {}
    for line in head.decode("latin1").split("\r\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return headers, rest


def ws_accept(key):
    return base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()


def read_frame(sock, buf):
    """Return (opcode, payload, leftover_buffer). Client frames are masked."""
    def take(n, b):
        while len(b) < n:
            chunk = sock.recv(65536)
            if not chunk:
                raise ConnectionError("closed")
            b += chunk
        return b[:n], b[n:]
    hdr, buf = take(2, buf)
    opcode = hdr[0] & 0x0F
    masked = hdr[1] & 0x80
    length = hdr[1] & 0x7F
    if length == 126:
        ext, buf = take(2, buf)
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext, buf = take(8, buf)
        length = struct.unpack(">Q", ext)[0]
    if length > MAX_FRAME:
        raise ValueError("frame too large")
    mask = b""
    if masked:
        mask, buf = take(4, buf)
    payload, buf = take(length, buf)
    if masked:
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return opcode, payload, buf


def send_frame(sock, payload, opcode=0x2):
    n = len(payload)
    if n < 126:
        hdr = struct.pack("BB", 0x80 | opcode, n)
    elif n < 65536:
        hdr = struct.pack(">BBH", 0x80 | opcode, 126, n)
    else:
        hdr = struct.pack(">BBQ", 0x80 | opcode, 127, n)
    sock.sendall(hdr + payload)


def connect_backend():
    last = None
    for addr in BACKENDS:
        try:
            s = socket.create_connection(addr, timeout=5)
            s.settimeout(None)
            return s
        except OSError as exc:
            last = exc
    raise last


def handle(client):
    backend = None
    try:
        headers, rest = read_http_headers(client)
        key = headers.get("sec-websocket-key")
        if not key:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        client.sendall((
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {ws_accept(key)}\r\n\r\n").encode())
        backend = connect_backend()

        stop = threading.Event()

        def backend_to_client():
            try:
                while not stop.is_set():
                    r, _, _ = select.select([backend], [], [], 30)
                    if not r:
                        continue
                    data = backend.recv(65536)
                    if not data:
                        break
                    send_frame(client, data, 0x2)
            except OSError:
                pass
            finally:
                stop.set()

        t = threading.Thread(target=backend_to_client, daemon=True)
        t.start()
        buf = rest
        while not stop.is_set():
            opcode, payload, buf = read_frame(client, buf)
            if opcode == 0x8:      # close
                break
            if opcode == 0x9:      # ping -> pong
                send_frame(client, payload, 0xA)
                continue
            if opcode in (0x1, 0x2, 0x0) and payload:
                backend.sendall(payload)
    except (ConnectionError, OSError, ValueError):
        pass
    finally:
        for s in (client, backend):
            try:
                if s:
                    s.close()
            except OSError:
                pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(LISTEN)
    srv.listen(128)
    print(f"ragnar wsproxy listening on {LISTEN[0]}:{LISTEN[1]}", flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
