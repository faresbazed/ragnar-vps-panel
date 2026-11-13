#!/bin/bash
# =====================================================================
# Ragnar VPS Management Panel - installer
# Telegram : @farisbazed      Channel : https://t.me/ragnaresim
#
# Usage (fresh Ubuntu 22.04/24.04 or Debian 11/12, as root):
#   git clone <this repo> && cd ragnar-vps-panel
#   sudo bash install.sh
#
# Non-interactive:
#   RAGNAR_DOMAIN=vpn.example.com RAGNAR_NS=ns.example.com sudo -E bash install.sh
# =====================================================================
set -u
PANEL="Ragnar VPS Management Panel"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE="/etc/ragnar"
log()  { echo -e "\033[96m[RAGNAR]\033[0m $*"; }
warn() { echo -e "\033[93m[RAGNAR]\033[0m $*"; }
die()  { echo -e "\033[91m[RAGNAR] $*\033[0m"; exit 1; }

[ "$(id -u)" = 0 ] || die "Run as root: sudo bash install.sh"
. /etc/os-release 2>/dev/null || die "Cannot read /etc/os-release"
case " $ID $ID_LIKE " in
    *ubuntu*|*debian*) : ;;
    *) warn "Tested on Ubuntu/Debian - continuing anyway" ;;
esac

# ---------------------------------------------------------------------
# Questions
# ---------------------------------------------------------------------
DOMAIN="${RAGNAR_DOMAIN:-}"
if [ -z "$DOMAIN" ] && [ -t 0 ]; then
    read -rp "Domain pointed at this VPS (blank = use IP, self-signed cert): " DOMAIN
fi
NS="${RAGNAR_NS:-}"
if [ -z "$NS" ] && [ -t 0 ]; then
    read -rp "SlowDNS nameserver (e.g. ns.yourdomain.com, blank = skip SlowDNS NS): " NS
fi

PUBIP=$(curl -s4 --max-time 8 https://api.ipify.org || hostname -I | awk '{print $1}')
HOST_FOR_LINKS="${DOMAIN:-$PUBIP}"
log "Installing $PANEL for host $HOST_FOR_LINKS (IP $PUBIP)"

# ---------------------------------------------------------------------
# Packages + tuning
# ---------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
# Repair a half-finished dpkg state first (a common fresh-VPS landmine:
# every apt install then fails with "dpkg was interrupted").
dpkg --configure -a 2>/dev/null || true
apt-get install -f -y >/dev/null 2>&1 || true
# Silence "sudo: unable to resolve host" on hosts without a hosts entry
grep -q " $(hostname)" /etc/hosts 2>/dev/null || echo "127.0.1.1 $(hostname)" >> /etc/hosts
apt-get update -y
apt-get install -y curl wget unzip tar jq python3 haproxy dropbear \
    openssh-server vnstat iptables socat openssl cron \
    certbot iproute2 net-tools procps ca-certificates gnupg \
    || die "Package installation failed - fix apt (try: sudo dpkg --configure -a) and re-run install.sh"
# NOTE: there is no 'badvpn' package in Ubuntu 24.04 - udpgw is fetched
# as the upstream prebuilt binary in the UDP Custom section below.
for bin in haproxy python3 openssl; do
    command -v "$bin" >/dev/null || die "$bin is missing after apt install - aborting before half-configuring the box"
done
# Download a binary atomically: fetch to a temp file in the same
# directory, then rename into place. A plain "wget -O <dest>" truncates
# the target and fails with "Text file busy" whenever the old binary is
# still running - the classic re-run-the-installer-over-a-live-panel
# failure that used to skip udp-custom and SlowDNS entirely.
fetch_bin() {
    local url="$1" dest="$2" tmp="${2}.tmp.$$"
    if wget -q "$url" -O "$tmp"; then
        chmod +x "$tmp" && mv -f "$tmp" "$dest"
    else
        rm -f "$tmp"; return 1
    fi
}
# Re-installing over a live panel: stop the services whose binaries are
# about to be replaced (all units are started again at the end).
for u in zivpn udp-custom badvpn-udpgw udpgw slowdns xray sing-box cloudflared ragnar-wsproxy; do
    systemctl stop "$u" 2>/dev/null || true
done
mkdir -p /etc/haproxy

install -m 644 "$SRC/configs/99-ragnar-tuning.conf" /etc/sysctl.d/99-ragnar-tuning.conf
sysctl --system >/dev/null 2>&1 || true
grep -q "ragnar" /etc/security/limits.conf || cat >> /etc/security/limits.conf <<'EOF'
# ragnar
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF
systemctl enable vnstat >/dev/null 2>&1 || true

mkdir -p "$BASE"/{db,core,certs,xray,sing-box,zivpn,udp,slowdns,web}
install -m 755 "$SRC/core/ragnar.py"   "$BASE/core/ragnar.py"
install -m 755 "$SRC/core/checker.py"  "$BASE/core/checker.py"
install -m 755 "$SRC/core/wsproxy.py"  "$BASE/core/wsproxy.py"
install -m 755 "$SRC/core/watchdog.sh" "$BASE/core/watchdog.sh"
install -m 755 "$SRC/core/ragnar-slowdns-setup" /usr/local/bin/ragnar-slowdns-setup
install -m 755 "$SRC/menu.sh"          "$BASE/menu.sh"
install -m 755 "$SRC/uninstall.sh"     "$BASE/uninstall.sh"
install -m 755 "$SRC/web/webpanel.py"  "$BASE/web/webpanel.py"
ln -sf "$BASE/menu.sh" /usr/local/bin/menu
ln -sf "$BASE/menu.sh" /usr/local/bin/ragnar
echo "$PUBIP" > "$BASE/host"
[ -n "$DOMAIN" ] && echo "$DOMAIN" > "$BASE/domain"
python3 - "$DOMAIN" "$NS" <<'PY'
import json, os, sys
p = "/etc/ragnar/settings.json"
s = json.load(open(p)) if os.path.exists(p) else {}
if sys.argv[1]: s["domain"] = sys.argv[1]
if sys.argv[2]: s["ns"] = sys.argv[2]
json.dump(s, open(p, "w"), indent=2)
PY

# ---------------------------------------------------------------------
# Certificates (Let's Encrypt if the domain resolves here, else self-signed)
# ---------------------------------------------------------------------
CERT_OK=0
if [ -n "$DOMAIN" ]; then
    DIP=$(getent hosts "$DOMAIN" | awk '{print $1}' | head -1)
    if [ "$DIP" = "$PUBIP" ]; then
        # certbot --standalone must bind port 80 itself: stop HAProxy if
        # a previous install left it running (the HAProxy section below
        # restarts it). Certbot output goes to a log file, never to
        # /dev/null - a silently swallowed certbot failure cost a real
        # debugging round on 2026-11-13 (broken python SSL stack on the
        # box, invisible behind the self-signed fallback).
        systemctl stop haproxy 2>/dev/null || true
        : > /tmp/ragnar-certbot.log
        # Preferred: one cert covering the domain AND anytls.<domain>.
        # If anytls.<domain> has no DNS record yet the whole order fails,
        # so fall back to a domain-only cert instead of self-signed.
        if certbot certonly --standalone --non-interactive --agree-tos \
                -m "admin@$DOMAIN" -d "$DOMAIN" -d "anytls.$DOMAIN" \
                >>/tmp/ragnar-certbot.log 2>&1; then
            CERT_OK=1; log "Let's Encrypt certificate installed (domain + anytls subdomain)"
        elif certbot certonly --standalone --non-interactive --agree-tos \
                -m "admin@$DOMAIN" -d "$DOMAIN" >>/tmp/ragnar-certbot.log 2>&1; then
            CERT_OK=1
            warn "Let's Encrypt certificate installed for $DOMAIN only."
            warn "Add an A record  anytls.$DOMAIN -> $PUBIP  and re-run install.sh"
            warn "so the AnyTLS name is covered too (AnyTLS needs that record anyway)."
        else
            warn "certbot failed - last lines of /tmp/ragnar-certbot.log:"
            tail -n 8 /tmp/ragnar-certbot.log 2>/dev/null | sed 's/^/    /'
        fi
        if [ "$CERT_OK" = 1 ]; then
            cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$BASE/certs/fullchain.pem"
            cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$BASE/certs/privkey.pem"
        fi
    fi
fi
if [ "$CERT_OK" = 0 ]; then
    warn "Using a self-signed certificate (clients: allow insecure / set SNI to the host)"
    openssl req -x509 -newkey rsa:2048 -keyout "$BASE/certs/privkey.pem" \
        -out "$BASE/certs/fullchain.pem" -days 3650 -nodes \
        -subj "/CN=$HOST_FOR_LINKS" \
        -addext "subjectAltName=DNS:$HOST_FOR_LINKS,IP:$PUBIP" 2>/dev/null
fi
cat "$BASE/certs/fullchain.pem" "$BASE/certs/privkey.pem" > "$BASE/certs/haproxy.pem"
chmod 600 "$BASE/certs/"*.pem "$BASE/certs/haproxy.pem"
# ZIVPN certificate (its own format/names)
openssl req -x509 -newkey rsa:2048 -keyout "$BASE/certs/zivpn.key" \
    -out "$BASE/certs/zivpn.crt" -days 3650 -nodes -subj "/CN=$HOST_FOR_LINKS" 2>/dev/null

# ---------------------------------------------------------------------
# SSH: OpenSSH 22 + Dropbear 109 (backends only; front door is HAProxy)
# ---------------------------------------------------------------------
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/60-ragnar.conf <<'EOF'
PasswordAuthentication yes
PermitTunnel yes
AllowTcpForwarding yes
GatewayPorts yes
X11Forwarding no
ClientAliveInterval 60
ClientAliveCountMax 10
MaxSessions 100
EOF
cat > /etc/default/dropbear <<'EOF'
NO_START=0
DROPBEAR_PORT=109
DROPBEAR_EXTRA_ARGS="-p 143 -W 65536"
DROPBEAR_BANNER=""
DROPBEAR_RECEIVE_WINDOW=1048576
EOF
systemctl enable --now ssh dropbear 2>/dev/null || \
    { systemctl enable --now sshd 2>/dev/null; systemctl restart dropbear; }

# Landing page (harmless "It works" page for plain HTTPS visitors on 443)
mkdir -p "$BASE/www"
cat > "$BASE/www/index.html" <<'EOF'
<html><head><title>Welcome</title></head><body><h3>It works.</h3></body></html>
EOF
cat > /etc/systemd/system/ragnar-landing.service <<'EOF'
[Unit]
Description=Ragnar landing page
After=network.target
[Service]
ExecStart=/usr/bin/python3 -m http.server 10080 --bind 127.0.0.1 --directory /etc/ragnar/www
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF

# SSH WebSocket proxy service
cat > /etc/systemd/system/ragnar-wsproxy.service <<'EOF'
[Unit]
Description=Ragnar SSH WebSocket proxy
After=network.target dropbear.service
[Service]
ExecStart=/usr/bin/python3 /etc/ragnar/core/wsproxy.py
Restart=always
RestartSec=2
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF

# ---------------------------------------------------------------------
# HAProxy front door (owns 80 + 443 - see configs/haproxy.cfg)
# ---------------------------------------------------------------------
cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak-ragnar 2>/dev/null || true
install -m 644 "$SRC/configs/haproxy.cfg" /etc/haproxy/haproxy.cfg
mkdir -p /run/haproxy /etc/systemd/system/haproxy.service.d
cat > /etc/systemd/system/haproxy.service.d/10-ragnar.conf <<'EOF'
[Service]
LimitNOFILE=1048576
EOF
systemctl daemon-reload
haproxy -c -f /etc/haproxy/haproxy.cfg || die "HAProxy config invalid - aborting"
# restart, not just enable --now: on a re-install HAProxy may already be
# running with the previous config in memory (observed live 2026-11-13:
# the new /panel routing sat on disk while the old process kept serving
# the old config, and the web panel 404'd until a manual restart).
systemctl enable haproxy
systemctl restart haproxy

# ---------------------------------------------------------------------
# Xray (VLESS / VMESS / Trojan / SSWS over WS) + sing-box (AnyTLS)
# ---------------------------------------------------------------------
if ! command -v xray >/dev/null; then
    bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install \
        || warn "Xray install failed - install it manually, then run: menu -> Tools -> Restart ALL"
fi
mkdir -p /usr/local/etc/xray
if ! command -v sing-box >/dev/null; then
    bash -c "$(curl -fsSL https://sing-box.app/install.sh)" \
        || warn "sing-box install failed - AnyTLS will stay offline until it is installed"
fi
cat > /etc/systemd/system/xray.service <<'EOF'
[Unit]
Description=Xray (Ragnar)
After=network.target
[Service]
ExecStart=/usr/local/bin/xray run -config /etc/ragnar/xray/config.json
Restart=always
RestartSec=2
LimitNOFILE=1048576
User=root
[Install]
WantedBy=multi-user.target
EOF
SINGBOX_BIN=$(command -v sing-box || echo /usr/local/bin/sing-box)
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
Description=sing-box AnyTLS (Ragnar)
After=network.target
[Service]
ExecStart=$SINGBOX_BIN run -c /etc/ragnar/sing-box/config.json
Restart=always
RestartSec=2
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
# AnyTLS direct fallback port (8446 -> sing-box backend, simple redirect)
iptables -t nat -C PREROUTING -p tcp --dport 8446 -j REDIRECT --to-ports 10006 2>/dev/null || \
    iptables -t nat -A PREROUTING -p tcp --dport 8446 -j REDIRECT --to-ports 10006

# ---------------------------------------------------------------------
# UDP ZIVPN (binary: zahidbd2/udp-zivpn) - optimized
# ---------------------------------------------------------------------
ARCH=$(uname -m); [ "$ARCH" = x86_64 ] && ZARCH=amd64 || ZARCH=arm64
# Pinned upstream release (zahidbd2/udp-zivpn) - the binary is invoked as
# "zivpn server -c <config>", exactly as upstream's own installer does.
ZURL="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-${ZARCH}"
if fetch_bin "$ZURL" /usr/local/bin/zivpn; then
    log "ZIVPN binary installed"
else
    warn "ZIVPN binary download failed - service created but it cannot start until /usr/local/bin/zivpn exists"
fi
cat > /etc/systemd/system/zivpn.service <<'EOF'
[Unit]
Description=UDP ZIVPN (Ragnar)
After=network.target
[Service]
Type=simple
User=root
WorkingDirectory=/etc/ragnar/zivpn
ExecStart=/usr/local/bin/zivpn server -c /etc/ragnar/zivpn/config.json
Restart=always
RestartSec=3
LimitNOFILE=1048576
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
[Install]
WantedBy=multi-user.target
EOF
# ZIVPN speed trick used by every fast panel: the client may hit any UDP
# port in 6000-19999; redirect the whole range onto the server port.
iptables -t nat -C PREROUTING -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667 2>/dev/null || \
    iptables -t nat -A PREROUTING -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667

# ---------------------------------------------------------------------
# UDP Custom (ePro binary, checksum-verified) + badvpn-udpgw
# ---------------------------------------------------------------------
if [ "$ARCH" = x86_64 ]; then
    if fetch_bin https://raw.githubusercontent.com/http-custom/udp-custom/main/bin/udp-custom-linux-amd64 \
            /usr/local/bin/udp-custom; then
        echo "2a1b5584c7947feb5a02e847e09795751024f63ce7137a353c2b9c2a4282d636  /usr/local/bin/udp-custom" \
            | sha256sum -c - >/dev/null 2>&1 \
            || warn "udp-custom checksum differs from the pinned upstream hash - keeping the binary, verify upstream before trusting it"
        chmod +x /usr/local/bin/udp-custom
    else
        warn "udp-custom download failed"
    fi
fi
python3 - <<'PY'
import json, os
# Optimized upstream-shaped config: 80 MB receive buffer, big stream buffer,
# SSH users mirrored as passwords-auth entries (user:pass).
cfg = {"listen": ":36712", "stream_buffer": 33554432, "receive_buffer": 83886080,
       "auth": {"mode": "passwords", "config": []}}
try:
    ssh = json.load(open("/etc/ragnar/db/ssh.json"))["users"]
    cfg["auth"]["config"] = [f"{u}:{d['password']}" for u, d in ssh.items()]
except Exception:
    pass
os.makedirs("/etc/ragnar/udp", exist_ok=True)
json.dump(cfg, open("/etc/ragnar/udp/config.json", "w"), indent=2)
PY
cat > /etc/systemd/system/udp-custom.service <<'EOF'
[Unit]
Description=UDP Custom by ePro Dev Team (Ragnar)
After=network.target
[Service]
WorkingDirectory=/etc/ragnar/udp
ExecStart=/usr/local/bin/udp-custom server
Restart=always
RestartSec=2
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
# BadVPN udpgw (the UDP gateway UDP Custom clients use for voice/games):
# a system badvpn-udpgw if one exists, else the upstream prebuilt BadVPN
# binary. Installed under its canonical name and service so it shows up
# as badvpn-udpgw everywhere (older Ragnar installs ran it as udpgw -
# migrate the binary and retire the old unit name).
UDPGW_BIN=$(command -v badvpn-udpgw || true)
if [ -z "$UDPGW_BIN" ]; then
    if [ -x /usr/local/bin/badvpn-udpgw ]; then
        UDPGW_BIN=/usr/local/bin/badvpn-udpgw
    elif [ -x /usr/local/bin/udpgw ]; then
        cp /usr/local/bin/udpgw /usr/local/bin/badvpn-udpgw
        UDPGW_BIN=/usr/local/bin/badvpn-udpgw
    elif fetch_bin https://raw.githubusercontent.com/http-custom/udp-custom/main/module/udpgw \
            /usr/local/bin/badvpn-udpgw; then
        UDPGW_BIN=/usr/local/bin/badvpn-udpgw
    else
        warn "badvpn-udpgw download failed - UDP gateway will stay offline"
        UDPGW_BIN=/usr/local/bin/badvpn-udpgw
    fi
fi
ln -sf "$UDPGW_BIN" /usr/local/bin/udpgw
if [ -f /etc/systemd/system/udpgw.service ]; then
    systemctl disable --now udpgw 2>/dev/null || true
    rm -f /etc/systemd/system/udpgw.service
fi
cat > /etc/systemd/system/badvpn-udpgw.service <<EOF
[Unit]
Description=BadVPN udpgw - UDP gateway for UDP Custom (Ragnar)
After=network.target
[Service]
ExecStart=$UDPGW_BIN --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 100
Restart=always
RestartSec=2
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
# UDP Custom clients can use any UDP port; NAT the range onto 36712
# (excluding ZIVPN's range and DNS).
iptables -t nat -C PREROUTING -p udp --dport 20000:65535 -j REDIRECT --to-ports 36712 2>/dev/null || \
    iptables -t nat -A PREROUTING -p udp --dport 20000:65535 -j REDIRECT --to-ports 36712
# Outbound NAT for tunnel users
iptables -t nat -C POSTROUTING -o "$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+')" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o "$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+')" -j MASQUERADE

# ---------------------------------------------------------------------
# SlowDNS - REPLACED WHOLESALE on 2026-11-13 at the user's request:
# the implementation from faresbazed/Ragnar-VPS-Management-Panel,
# byte-for-byte. core/ragnar-slowdns-setup is the other panel's own
# setup script, extracted verbatim (it builds the turbo-patched
# dnstt-server, manages keys + config files in /etc/vps-panel/slowdns/,
# writes the slowdns unit and restarts it). The only glue here is
# seeding that config dir from this panel's existing SlowDNS identity
# (so an upgrade keeps the same keypair/nameserver) and mirroring the
# resulting public key back into settings.json for other displays.
# ---------------------------------------------------------------------
mkdir -p /etc/vps-panel/slowdns
for f in server.key server.pub; do
    if [ ! -s "/etc/vps-panel/slowdns/$f" ] && [ -s "$BASE/slowdns/$f" ]; then
        cp "$BASE/slowdns/$f" "/etc/vps-panel/slowdns/$f"
    fi
done
chmod 600 /etc/vps-panel/slowdns/server.key 2>/dev/null || true
python3 - <<'PYEOF2'
import json, os
base = "/etc/vps-panel/slowdns"
p = "/etc/ragnar/settings.json"
s = json.load(open(p)) if os.path.exists(p) else {}
seed = {
    "nameserver": s.get("ns") or "",
    "mtu": str(s.get("slowdns_mtu") or "1232"),
    "dns_resolver": s.get("slowdns_resolver") or "1.1.1.1",
    "target_port": str(s.get("slowdns_target") or "22"),
}
for name, val in seed.items():
    fp = os.path.join(base, name)
    if val and not (os.path.exists(fp) and os.path.getsize(fp) > 0):
        open(fp, "w").write(val + "\n")
PYEOF2
# Their installer's own invocation: NS, no CF token, MTU 1232.
/usr/local/bin/ragnar-slowdns-setup "${NS:-}" "" "1232" || \
    warn "SlowDNS setup failed - re-run: /usr/local/bin/ragnar-slowdns-setup"
python3 - <<'PYEOF3'
import json, os
p = "/etc/ragnar/settings.json"
s = json.load(open(p)) if os.path.exists(p) else {}
pub = "/etc/vps-panel/slowdns/server.pub"
if os.path.exists(pub):
    s["slowdns_pubkey"] = open(pub).read().strip()
json.dump(s, open(p, "w"), indent=2)
PYEOF3

# ---------------------------------------------------------------------
# Cloudflared
# ---------------------------------------------------------------------
if ! command -v cloudflared >/dev/null; then
    wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${ZARCH}.deb \
        -O /tmp/cloudflared.deb && dpkg -i /tmp/cloudflared.deb 2>/dev/null \
        || warn "cloudflared install failed - get it from cloudflare.com"
    rm -f /tmp/cloudflared.deb
fi

# ---------------------------------------------------------------------
# Limit checker + watchdog timers (every minute)
# ---------------------------------------------------------------------
cat > /etc/systemd/system/ragnar-check.service <<'EOF'
[Unit]
Description=Ragnar limit checker (expiry / GB quota / IP limit)
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /etc/ragnar/core/checker.py --apply
EOF
cat > /etc/systemd/system/ragnar-check.timer <<'EOF'
[Unit]
Description=Run Ragnar limit checker every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
EOF
cat > /etc/systemd/system/ragnar-watchdog.service <<'EOF'
[Unit]
Description=Ragnar service watchdog
[Service]
Type=oneshot
ExecStart=/bin/bash /etc/ragnar/core/watchdog.sh
EOF
cat > /etc/systemd/system/ragnar-watchdog.timer <<'EOF'
[Unit]
Description=Run Ragnar watchdog every minute
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
EOF

# ---------------------------------------------------------------------
# Firewall (only when UFW is active - never lock the admin out)
# ---------------------------------------------------------------------
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    for p in 22/tcp 80/tcp 443/tcp 109/tcp 143/tcp 53 53/udp 53/tcp 5667/udp \
             36712/udp 6000:19999/udp 20000:65535/udp 8446/tcp 2053/tcp; do
        ufw allow "$p" >/dev/null 2>&1 || true
    done
fi
# Same protection when UFW's chains are loaded and enforcing but
# `ufw status` does not report active (observed live 2026-11-13 on the
# hosting.de box: ufw-user-input held only fossil rules for 22/53/8080/
# 8081, so the whole panel - 80/443 included - was unreachable from
# outside and Let's Encrypt validation timed out, while the block
# above silently skipped). The UDP port ranges are NAT-redirected to
# 5667/36712 before INPUT, so those two ports cover them here.
if iptables -S ufw-user-input >/dev/null 2>&1; then
    for spec in "tcp 22" "tcp 80" "tcp 443" "tcp 109" "tcp 143" \
                "tcp 53" "udp 53" "udp 5667" "udp 36712" \
                "tcp 8446" "tcp 2053"; do
        set -- $spec
        iptables -C ufw-user-input -p "$1" --dport "$2" -j ACCEPT 2>/dev/null || \
            iptables -A ufw-user-input -p "$1" --dport "$2" -j ACCEPT 2>/dev/null || true
    done
fi
# persist iptables NAT rules across reboots
apt-get install -y iptables-persistent >/dev/null 2>&1 || true
netfilter-persistent save >/dev/null 2>&1 || \
    iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

# ---------------------------------------------------------------------
# Generate configs + start everything
# ---------------------------------------------------------------------
RAGNAR_DIR="$BASE" python3 "$BASE/core/ragnar.py" gen-configs || true
cp "$BASE/xray/config.json" /usr/local/etc/xray/config.json 2>/dev/null || true

# ---------------------------------------------------------------------
# Web panel (3x-ui style, HTTPS :2053 with the domain certificate)
# ---------------------------------------------------------------------
cat > /etc/systemd/system/ragnar-web.service <<'EOF'
[Unit]
Description=Ragnar Web Panel
After=network.target
[Service]
Type=simple
Environment=RAGNAR_DIR=/etc/ragnar
Environment=RAGNAR_WEB_BIND=127.0.0.1
Environment=RAGNAR_WEB_NO_TLS=1
Environment=RAGNAR_WEB_BASE=/panel
ExecStart=/usr/bin/python3 /etc/ragnar/web/webpanel.py
Restart=on-failure
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF
RAGNAR_DIR="$BASE" python3 "$BASE/web/webpanel.py" --init || true

systemctl daemon-reload
for svc in haproxy ssh dropbear ragnar-wsproxy ragnar-landing xray sing-box zivpn \
           udp-custom badvpn-udpgw slowdns ragnar-check.timer ragnar-watchdog.timer \
           ragnar-web; do
    systemctl enable --now "$svc" 2>/dev/null || warn "could not start $svc (check: systemctl status $svc)"
done

cat <<EOF

=====================================================================
  $PANEL installed.
  Open the panel with:      menu        (or: ragnar)
  Web panel (HTTPS)   :     https://<your-domain>/panel
                            (served through HAProxy on 443, so it works
                            even where the provider firewalls port 2053;
                            login printed above by --init; reset any
                            time from menu > WEB PANEL > RESET ADMIN
                            PASSWORD)

  Ports
    22/tcp    SSH direct          109/tcp  Dropbear
    80/tcp    WS  (all protocols + SSH-WS, routed by path)
    443/tcp   WSS / SSH-SSL / AnyTLS-SNI (HAProxy front door)
    53        SlowDNS (DNSTT -> SSH)
    5667/udp  ZIVPN (+ 6000-19999/udp redirected)
    36712/udp UDP Custom (+ 20000-65535/udp redirected), badvpn-udpgw 7300
    8446/tcp  AnyTLS fallback

  Telegram : @farisbazed
  Channel  : https://t.me/ragnaresim
=====================================================================
EOF
