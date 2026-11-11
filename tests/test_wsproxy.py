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
def fake_ssh():
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 109)); srv.listen(1)
    conn, _ = srv.accept()
    conn.sendall(b"SSH-2.0-FakeSSH\r\n")
    data = conn.recv(4096)
    received.append(data)
    conn.sendall(b"echo:" + data)
    time.sleep(0.3); conn.close(); srv.close()

t = threading.Thread(target=fake_ssh, daemon=True); t.start()
time.sleep(0.2)

env = dict(os.environ, RAGNAR_WSPORT="10005")
proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "core", "wsproxy.py")],
                        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
try:
    time.sleep(0.6)
    cli = socket.create_connection(("127.0.0.1", 10005), timeout=5)
    key = base64.b64encode(os.urandom(16)).decode()
    cli.sendall((f"GET /ragnar-sshws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
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
    print("WSPROXY TEST PASSED (handshake, banner, masked frame round-trip)")
finally:
    proc.terminate()
