# Ragnar VPS Management Panel

**Telegram:** [@farisbazed](https://t.me/farisbazed) · **Channel:** [t.me/ragnaresim](https://t.me/ragnaresim)

A complete VPS panel in the style of the classic SSH/Xray autoscripts —
one menu that runs SSH, WebSocket, SSL, Xray, Cloudflare, UDP and SlowDNS
together **without the ports fighting each other**.

![look](docs/look.txt) — the menu mirrors the reference design: server
specs / ISP / bandwidth / user stats / service status on top, main menu
below, purple borders with cyan/green/yellow text.

## Install

Fresh **Ubuntu 22.04 / 24.04** or **Debian 11 / 12**, as root:

```bash
git clone https://github.com/faresbazed/ragnar-vps-panel.git
cd ragnar-vps-panel
sudo bash install.sh
```

The installer asks for a domain (optional — blank uses the IP with a
self-signed cert) and a SlowDNS nameserver (optional). Non-interactive:

```bash
RAGNAR_DOMAIN=vpn.example.com RAGNAR_NS=ns.example.com sudo -E bash install.sh
```

Then open the panel any time with:

```bash
menu        # or: ragnar
```

Uninstall from the menu (option **16**) or `sudo bash /etc/ragnar/uninstall.sh`.

## The port-sharing solution

Only **HAProxy binds 80 and 443**. Everything else is loopback-only,
health-checked, and revived by a watchdog every minute:

| Stage | What happens |
|---|---|
| 443 arrives | HAProxy peeks at the TLS **SNI**: `anytls.*` → sing-box AnyTLS (raw TLS passthrough). Everything else → stage 2 |
| Stage 2 (TLS terminated) | First bytes inspected: `GET /ragnar-vless` etc. → that Xray protocol; other `GET` → landing page; **not HTTP at all → SSH backend** (that's SSH-over-SSL) |
| 80 arrives | Same path routing without TLS; unknown paths fall through to the SSH-WS proxy so payload apps keep working |

So SSH-SSL, WSS and AnyTLS genuinely share 443, and no service can kill
another by grabbing its port. Backends: OpenSSH 22, Dropbear 109,
SSH-WS proxy 10005, Xray 10001–10004, AnyTLS 10006 (plus 8446 fallback).

## Features

### SSH & SSL users
- Create / list / **edit** / delete / renew users (real Linux accounts)
- **Per-user GB quota** (iptables owner-match counters, checked every minute)
- **Per-user IP limit** (extra source IPs get their sessions kicked)
- Expiry in days, enable/disable, password change
- User info sheet: host, ports, WS path, SNI, SlowDNS NS + public key
- **Two SSH-WS flavours, both on 80/443** — the proxy is hybrid:
  - `/ragnar-sshws` — **payload/raw mode** for NPV Tunnel, HTTP Custom,
    HA Tunnel etc. *Any* payload works: the proxy answers 101 to any
    request head (no Sec-WebSocket-Key required, any method, LF or CRLF)
    and then pipes raw SSH bytes, exactly like the classic panel proxies.
  - `/ragnar-sshwsf` — **true WebSocket framing** for NapsternetV-style
    WS clients (proper handshake, masked binary frames).
  - Any other path auto-detects from the first bytes the client sends.

### Xray — all protocols from one user
Creating one Xray user generates **all of these at the same time**, each
with links for **direct WS 80, direct WSS 443, Cloudflare WS 80 and
Cloudflare WSS 443**:

- **VLESS** · **VMESS** · **Trojan** · **SSWS** (Shadowsocks 2022) — Xray-core, WebSocket transport
- **AnyTLS** — via a sing-box sidecar (Xray-core has no AnyTLS; anyone
  telling you otherwise is selling you a config Xray will reject).
  AnyTLS is raw TLS, so it is direct-only on 443 (SNI-routed) / 8446 —
  Cloudflare's HTTP proxy cannot carry it.

Per-user expiry, GB quota (Xray Stats API counters) and edit/renew work
the same as SSH.

### Cloudflared
Menu **11**: set the domain, set the hostname used in Cloudflare links,
install a named-tunnel token, or start a quick trycloudflare tunnel.
Point the tunnel at `http://127.0.0.1:80` (the HAProxy front door) —
one tunnel then carries every WS protocol.

### UDP, optimized
Applied at install: BBR + fq, 64 MB socket buffers, big backlogs,
conntrack headroom, `LimitNOFILE` everywhere.

- **UDP ZIVPN** — server on 5667, per-user passwords, whole client port
  range **6000–19999 redirected** to it, self-signed cert generated.
- **UDP Custom** (ePro binary, SHA-256 verified against the pinned
  upstream hash) — listen 36712 with the upstream-optimized 80 MB
  receive buffer, ports **20000–65535 redirected** to it, badvpn-udpgw
  on 7300, SSH users mirrored as auth entries.
- **SlowDNS** (DNSTT) — UDP/TCP 53 redirected to dnstt on 5300 →
  SSH 22; keypair generated at install, public key shown in the menu.

### Panel
- Header: VPS IP, ISP, OS, uptime, CPU/RAM/disk, server time, bandwidth,
  user stats (per protocol + total + online) and live service status
- **Tools:** restart all services, user backup, run the limit checker,
  speed test, listening ports
- **Clear RAM**, **Reboot VPS**, **Uninstall** — all in the menu
- `ragnar-check.timer` enforces expiry/quota/IP limits every minute;
  `ragnar-watchdog.timer` restarts any dead service every minute

## Ports

| Port | Service |
|---|---|
| 22/tcp | SSH direct |
| 109, 143/tcp | Dropbear |
| 80/tcp | WS — all protocols + SSH-WS (HAProxy) |
| 443/tcp | WSS + SSH-SSL + AnyTLS SNI (HAProxy) |
| 8446/tcp | AnyTLS fallback |
| 53 udp/tcp | SlowDNS |
| 5667/udp (+6000–19999) | ZIVPN |
| 36712/udp (+20000–65535) | UDP Custom |
| 7300 (loopback) | badvpn-udpgw |

## Layout

```
menu.sh            the panel (installed as `menu` / `ragnar`)
install.sh         one-shot installer        uninstall.sh
core/ragnar.py     user DBs, config + link generation (stdlib only)
core/checker.py    expiry / quota / IP-limit enforcer (1-minute timer)
core/wsproxy.py    SSH-over-WebSocket proxy (stdlib only)
core/watchdog.sh   dead-service reviver (1-minute timer)
configs/           HAProxy front door + sysctl tuning
tests/             local tests: python3 tests/test_ragnar.py
                   python3 tests/test_wsproxy.py
```

## Verification done locally (before any VPS)

- Core unit tests: 21 checks (users, edits, links, config, enforcement)
- Generated Xray config validated with **real Xray 25.10.15**, and all
  four WS protocols tunnelled live traffic through it
- Generated sing-box config validated with **real sing-box 1.12.9**;
  AnyTLS tunnelled live traffic, both direct and through HAProxy's
  443 SNI passthrough
- HAProxy config validated with **real HAProxy 2.8**, and a live
  front-door test passed all at once: SSH-WS on 80, SSH-WSS on 443,
  raw SSH-SSL banner on 443, HTTPS landing on 443, VLESS on 80 and 443

What still needs a real VPS: the systemd installer end-to-end, the
closed-source UDP binaries (ZIVPN / UDP Custom download at install time),
SlowDNS over a real NS delegation, and Cloudflared with a real tunnel
token — the sandbox here cannot answer UDP or run systemd.
