#!/usr/bin/env python3
"""
Ragnar SSH WebSocket proxy (stdlib only) - hybrid edition.

Listens on 127.0.0.1:10005 and bridges to the local SSH backend
(Dropbear 127.0.0.1:109, falling back to OpenSSH 127.0.0.1:22).
HAProxy terminates TLS in front of it, so the same backend serves both
WS (port 80) and WSS (port 443) on path /ragnar-sshws.

Why "hybrid": SSH apps come in two families and this proxy serves both.

  1. Payload apps (NPV Tunnel, HTTP Custom, HA Tunnel Plus, ZIVPN...).
     They send a hand-written HTTP payload ("GET ... Upgrade: websocket",
     often WITHOUT Sec-WebSocket-Key, sometimes with another method, LF
     line endings, or the request split across packets), expect a
     "101 Switching Protocols" reply, and then speak RAW SSH bytes -
     no WebSocket framing at all. Any payload works.

  2. True WebSocket clients (NapsternetV WS mode, v2ray-style libs).
     Proper handshake with Sec-WebSocket-Key, then masked binary frames.

After the 101 reply the proxy sniffs the first client bytes: a masked
frame (0x8x + mask bit) selects framed mode, anything else (e.g. the
"SSH-2.0-..." client version string) selects raw mode. The SSH banner
is buffered for up to 300 ms while the mode is undecided.
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
FRAME_FIRST_BYTES = {0x80, 0x81, 0x82, 0x88, 0x89, 0x8A}


def recv_exact(sock, n, buf):
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf[:n], buf[n:]


def _split_head(data):
    """(head, rest, sep_len) for the first complete request head, or None."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in data:
            head, _, rest = data.partition(sep)
            return head, rest, len(sep)
    return None


def _parse_head(head):
    lines = head.replace(b"\r\n", b"\n").split(b"\n")
    parts = lines[0].split(b" ")
    path = parts[1].decode("latin1") if len(parts) > 1 else "/"
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower().decode("latin1")] = \
                v.strip().decode("latin1")
    return path, headers


def _looks_like_request(head):
    first = head.split(b"\n", 1)[0]
    parts = first.split(b" ")
    return len(parts) >= 3 and parts[-1].startswith(b"HTTP/")


def read_request(sock):
    """Read the tunnel request, tolerating real-world payload shapes.

    Payload apps often send TWO chained request heads in one stream:
    a decoy first request (bug-host trick) and then the real upgrade
    request - whose method may even be a made-up word. Forwarding the
    second head to SSH as raw bytes would corrupt the SSH handshake
    ("protocol mismatch"), so: parse every complete head in the stream,
    discard the decoys, answer 101 to the LAST head, and treat only the
    bytes after it as client stream data.

    Returns (path, headers, rest).
    """
    data = b""
    chained = False
    while _split_head(data) is None:
        if len(data) > 65536:
            raise ValueError("request head too large")
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("closed during handshake")
        data += chunk

    head, rest, _ = _split_head(data)
    genuine_ws = (b"sec-websocket-key" in head.lower()
                  and b"sec-websocket-version" in head.lower())
    if not genuine_ws:
        # Drain briefly: a chained second request may arrive split.
        # But stop the moment the final (Upgrade) head is fully in the
        # buffer - waiting out the full window delayed the 101 and the
        # SSH banner by ~350 ms, which strict apps / carrier hops
        # punish by dropping the connection.
        sock.settimeout(0.35)
        try:
            while len(data) < 65536:
                # The final head may already be fully buffered (both
                # requests arrived in one packet) - check BEFORE
                # blocking on recv, not only after new data lands.
                first = _split_head(data)
                if first is not None and len(first[1]) > 4:
                    nxt = _split_head(first[1])
                    if nxt is not None and b"upgrade" in nxt[0].lower():
                        break
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, TimeoutError):
            pass
        finally:
            sock.settimeout(None)
        # Walk the chain: keep the last complete request head.
        while True:
            parts = _split_head(data)
            if parts is None:
                break
            head, rest, _ = parts
            nxt = _split_head(rest)
            if nxt is not None and _looks_like_request(nxt[0]):
                data = rest
                chained = True
                continue
            break
    path, headers = _parse_head(head)
    return path, headers, rest, chained


def send_101(client, headers):
    lines = ["HTTP/1.1 101 Switching Protocols",
             "Upgrade: websocket", "Connection: Upgrade"]
    key = headers.get("sec-websocket-key")
    if key:
        accept = base64.b64encode(
            hashlib.sha1((key + GUID).encode()).digest()).decode()
        lines.append(f"Sec-WebSocket-Accept: {accept}")
    client.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())


def read_frame(sock, buf):
    hdr, buf = recv_exact(sock, 2, buf)
    opcode = hdr[0] & 0x0F
    masked = hdr[1] & 0x80
    length = hdr[1] & 0x7F
    if length == 126:
        ext, buf = recv_exact(sock, 2, buf)
        length = struct.unpack(">H", ext)[0]
    elif length == 127:
        ext, buf = recv_exact(sock, 8, buf)
        length = struct.unpack(">Q", ext)[0]
    if length > MAX_FRAME:
        raise ValueError("frame too large")
    mask = b""
    if masked:
        mask, buf = recv_exact(sock, 4, buf)
    payload, buf = recv_exact(sock, length, buf)
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
        path, headers, rest, chained = read_request(client)
        # Lenient by design: ANY request head gets a 101 and a tunnel.
        # Payload apps are not RFC WebSocket clients and must not be
        # rejected for a missing key / version / Upgrade header.
        send_101(client, headers)
        backend = connect_backend()

        mode = {"framed": None}          # None=undecided, True, False(raw)
        mode_ready = threading.Event()
        # The path can force the mode deterministically:
        #   /ragnar-sshws  -> raw payload mode (NPV Tunnel, HTTP Custom)
        #   /ragnar-sshwsf -> true WebSocket framing (NapsternetV WS mode)
        # Any other path: sniff the first client bytes, default raw.
        if path.startswith("/ragnar-sshwsf"):
            mode["framed"] = True
            mode_ready.set()
        elif path.startswith("/ragnar-sshws"):
            mode["framed"] = False
            mode_ready.set()
        elif chained:
            # A chained decoy payload is always a payload app speaking
            # raw SSH - never framed. Skip the mode sniff entirely so
            # the SSH banner is flushed the instant it arrives; some
            # carrier middleboxes and apps drop the connection if the
            # banner waits behind the ~300 ms sniff window.
            mode["framed"] = False
            mode_ready.set()
        stop = threading.Event()
        pending_banner = []

        def decide(first_bytes):
            if mode["framed"] is None:
                framed = (len(first_bytes) >= 2
                          and first_bytes[0] in FRAME_FIRST_BYTES
                          and bool(first_bytes[1] & 0x80))
                mode["framed"] = framed
                mode_ready.set()

        def backend_to_client():
            try:
                while not stop.is_set():
                    if backend.fileno() < 0:
                        break
                    r, _, _ = select.select([backend], [], [], 0.05)
                    if backend in r:
                        data = backend.recv(65536)
                        if not data:
                            break
                        if mode["framed"] is None:
                            pending_banner.append(data)
                            # give the client 300 ms to reveal its mode
                            if not mode_ready.wait(0.3):
                                mode["framed"] = False
                                mode_ready.set()
                        if mode["framed"]:
                            for chunk in pending_banner:
                                send_frame(client, chunk)
                            pending_banner.clear()
                            send_frame(client, data)
                        else:
                            for chunk in pending_banner:
                                client.sendall(chunk)
                            pending_banner.clear()
                            client.sendall(data)
                    elif pending_banner and mode["framed"] is not None:
                        flush = pending_banner.copy()
                        pending_banner.clear()
                        for chunk in flush:
                            if mode["framed"]:
                                send_frame(client, chunk)
                            else:
                                client.sendall(chunk)
            except (OSError, ValueError):
                # ValueError: the main thread closed the backend socket
                # (fd becomes -1) while we were selecting on it - that
                # is a normal teardown race, not an error.
                pass
            finally:
                stop.set()

        t = threading.Thread(target=backend_to_client, daemon=True)
        t.start()

        buf = rest
        if buf:
            decide(buf)
            if not mode["framed"]:
                backend.sendall(buf)
                buf = b""
        while not stop.is_set():
            if mode["framed"]:
                opcode, payload, buf = read_frame(client, buf)
                if opcode == 0x8:
                    break
                if opcode == 0x9:
                    send_frame(client, payload, 0xA)
                    continue
                if opcode in (0x0, 0x1, 0x2) and payload:
                    backend.sendall(payload)
            else:
                r, _, _ = select.select([client], [], [], 30)
                if client not in r:
                    continue
                data = client.recv(65536)
                if not data:
                    break
                if mode["framed"] is None:
                    decide(data)
                    if mode["framed"]:
                        buf = data       # re-parse as frames
                        continue
                backend.sendall(data)
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
    print(f"ragnar wsproxy (hybrid) listening on {LISTEN[0]}:{LISTEN[1]}", flush=True)
    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
