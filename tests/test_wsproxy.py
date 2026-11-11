#!/usr/bin/env python3
"""End-to-end test of the SSH WebSocket proxy against a fake SSH server."""
import base64
import hashlib
import os
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = os.path.join(os.path.dirname(__file__), "..")

# --- fake SSH backend on 127.0.0.1:109 (dropbear's port) ---------------
received = []
def _serve(conn):
    try:
        conn.sendall(b"SSH-2.0-FakeSSH\r\n")
        data = conn.recv(4096)
        if data:
            received.append(data)
            conn.sendall(b"echo:" + data)
        time.sleep(0.3)
    except OSError:
        pass
    finally:
        conn.close()

def fake_ssh():
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 109)); srv.listen(5)
    while True:
        try:
            conn, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=_serve, args=(conn,), daemon=True).start()

t = threading.Thread(target=fake_ssh, daemon=True); t.start()
time.sleep(0.2)

env = dict(os.environ, RAGNAR_WSPORT="10005")
proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "core", "wsproxy.py")],
                        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    time.sleep(0.6)
    cli = socket.create_connection(("127.0.0.1", 10005), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    cli.sendall((f"GET /ragnar-sshwsf HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
                 f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
                 f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += cli.recv(4096)
    assert b"101" in resp.split(b"\r\n")[0], resp
    accept = base64.b64encode(hashlib.sha1(
        (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest())
    assert accept in resp, "Sec-WebSocket-Accept mismatch"

    # first frame from server should be the SSH banner (binary frame)
    def read_frame(s):
        hdr = s.recv(2)
        ln = hdr[1] & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", s.recv(2))[0]
        payload = b""
        while len(payload) < ln:
            payload += s.recv(ln - len(payload))
        return payload
    banner = read_frame(cli)
    assert banner.startswith(b"SSH-2.0-"), banner

    # send a masked client frame, expect it forwarded and echoed back
    payload = b"hello-ssh"
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    cli.sendall(struct.pack("BB", 0x82, 0x80 | len(payload)) + mask + masked)
    echo = read_frame(cli)
    assert echo == b"echo:" + payload, echo
    assert received and received[0] == payload, received
    print("FRAMED MODE PASSED (handshake, banner, masked frame round-trip)")

    # ---- payload-app mode: no Sec-WebSocket-Key, raw bytes after 101 --
    cli2 = socket.create_connection(("127.0.0.1", 10005), timeout=5)
    cli2.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n"
                 b"Upgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += cli2.recv(4096)
    assert b"101" in resp.split(b"\r\n")[0], resp
    banner = cli2.recv(64)
    assert banner.startswith(b"SSH-2.0-"), banner          # RAW, not framed
    cli2.sendall(b"raw-ssh-bytes")                          # RAW client data
    echo = cli2.recv(64)
    assert echo == b"echo:raw-ssh-bytes", echo
    cli2.close()
    print("RAW PAYLOAD MODE PASSED (no key, 101, raw banner + raw echo)")

    # ---- payload with LF-only line endings ------------------------------
    cli3 = socket.create_connection(("127.0.0.1", 10005), timeout=5)
    cli3.sendall(b"GET / HTTP/1.0\nHost: x\nUpgrade: websocket\n\n")
    resp = cli3.recv(4096)
    assert b"101" in resp.split(b"\n")[0], resp
    assert cli3.recv(64).startswith(b"SSH-2.0-")
    cli3.close()
    print("LF PAYLOAD MODE PASSED")
    print("ALL WSPROXY TESTS PASSED")
finally:
    proc.terminate()
