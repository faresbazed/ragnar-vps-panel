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
apt-get update -y
apt-get install -y curl wget unzip tar jq python3 haproxy dropbear \
    openssh-server vnstat iptables socat openssl cron badvpn \
    certbot iproute2 net-tools procps ca-certificates gnupg

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

mkdir -p "$BASE"/{db,core,certs,xray,sing-box,zivpn,udp,slowdns}
install -m 755 "$SRC/core/ragnar.py"   "$BASE/core/ragnar.py"
install -m 755 "$SRC/core/checker.py"  "$BASE/core/checker.py"
install -m 755 "$SRC/core/wsproxy.py"  "$BASE/core/wsproxy.py"
install -m 755 "$SRC/core/watchdog.sh" "$BASE/core/watchdog.sh"
install -m 755 "$SRC/menu.sh"          "$BASE/menu.sh"
install -m 755 "$SRC/uninstall.sh"     "$BASE/uninstall.sh"
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
        if certbot certonly --standalone --non-interactive --agree-tos \
                -m "admin@$DOMAIN" -d "$DOMAIN" -d "anytls.$DOMAIN" 2>/dev/null; then
            cp "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$BASE/certs/fullchain.pem"
            cp "/etc/letsencrypt/live/$DOMAIN/privkey.pem"   "$BASE/certs/privkey.pem"
            CERT_OK=1; log "Let's Encrypt certificate installed"
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
systemctl enable --now haproxy

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
cat > /etc/systemd/system/sing-box.service <<'EOF'
[Unit]
Description=sing-box AnyTLS (Ragnar)
After=network.target
[Service]
ExecStart=/usr/local/bin/sing-box run -c /etc/ragnar/sing-box/config.json
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
ZURL=$(curl -s --max-time 15 https://api.github.com/repos/zahidbd2/udp-zivpn/releases/latest \
    | grep -o "https://[^\"]*linux-${ZARCH}[^\"]*" | head -1)
if [ -n "$ZURL" ] && wget -q "$ZURL" -O /usr/local/bin/ragnar-zivpn; then
    chmod +x /usr/local/bin/ragnar-zivpn
else
    warn "ZIVPN binary download failed - service created but disabled until the binary exists at /usr/local/bin/ragnar-zivpn"
fi
cat > /etc/systemd/system/zivpn.service <<'EOF'
[Unit]
Description=UDP ZIVPN (Ragnar)
After=network.target
[Service]
WorkingDirectory=/etc/ragnar/zivpn
ExecStart=/usr/local/bin/ragnar-zivpn
Restart=always
RestartSec=2
LimitNOFILE=1048576
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
    if wget -q https://raw.githubusercontent.com/http-custom/udp-custom/main/bin/udp-custom-linux-amd64 \
            -O /usr/local/bin/udp-custom; then
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
cat > /etc/systemd/system/udpgw.service <<'EOF'
[Unit]
Description=badvpn-udpgw for UDP Custom (Ragnar)
After=network.target
[Service]
ExecStart=/usr/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 100
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
# SlowDNS (DNSTT/SLDNS build) - SSH over DNS on 53
# ---------------------------------------------------------------------
if wget -q https://raw.githubusercontent.com/fisabiliyusri/SLDNS/master/slowdns/linux/slowdns \
        -O /usr/local/bin/slowdns; then
    chmod +x /usr/local/bin/slowdns
    if [ ! -f "$BASE/slowdns/server.key" ]; then
        (cd "$BASE/slowdns" && /usr/local/bin/slowdns -gen-key \
            -privkey-file server.key -pubkey-file server.pub)
    fi
    PUBKEY=$(cat "$BASE/slowdns/server.pub" 2>/dev/null || true)
    python3 - "$PUBKEY" <<'PY'
import json, os, sys
p = "/etc/ragnar/settings.json"
s = json.load(open(p)) if os.path.exists(p) else {}
s["slowdns_pubkey"] = sys.argv[1]
json.dump(s, open(p, "w"), indent=2)
PY
else
    warn "SlowDNS binary download failed - module skipped"
fi
cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=SlowDNS DNSTT (Ragnar)
After=network.target
[Service]
ExecStart=/usr/local/bin/slowdns -udp :5300 -tcp :5300 -privkey-file $BASE/slowdns/server.key ${NS:-ns.invalid} 127.0.0.1:22
Restart=always
RestartSec=2
LimitNOFILE=1048576
[Install]
WantedBy=multi-user.target
EOF
for proto in udp tcp; do
    iptables -t nat -C PREROUTING -p $proto --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || \
        iptables -t nat -A PREROUTING -p $proto --dport 53 -j REDIRECT --to-ports 5300
done

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
             36712/udp 6000:19999/udp 20000:65535/udp 8446/tcp; do
        ufw allow "$p" >/dev/null 2>&1 || true
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
systemctl daemon-reload
for svc in haproxy ssh dropbear ragnar-wsproxy ragnar-landing xray sing-box zivpn \
           udp-custom udpgw slowdns ragnar-check.timer ragnar-watchdog.timer; do
    systemctl enable --now "$svc" 2>/dev/null || warn "could not start $svc (check: systemctl status $svc)"
done

cat <<EOF

=====================================================================
  $PANEL installed.
  Open the panel with:      menu        (or: ragnar)

  Ports
    22/tcp    SSH direct          109/tcp  Dropbear
    80/tcp    WS  (all protocols + SSH-WS, routed by path)
    443/tcp   WSS / SSH-SSL / AnyTLS-SNI (HAProxy front door)
    53        SlowDNS (DNSTT -> SSH)
    5667/udp  ZIVPN (+ 6000-19999/udp redirected)
    36712/udp UDP Custom (+ 20000-65535/udp redirected), udpgw 7300
    8446/tcp  AnyTLS fallback

  Telegram : @farisbazed
  Channel  : https://t.me/ragnaresim
=====================================================================
EOF
