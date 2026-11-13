#!/usr/bin/env bash
# =====================================================================
# Ragnar SlowDNS setup - the Ragnar-VPS-Management-Panel SlowDNS,
# integrated into this panel's environment (2026-11-13).
#
# Everything functional is that panel's code, kept intact:
#   * turbo-patched dnstt-server build (their sed patch, verbatim):
#     turbotunnel QueueSize = 1024, smux buffers 4 MB,
#     KCP SetNoDelay(1, 10, 2, 1) + SetWindowSize(1024, 1024)
#   * their sysctl UDP buffer step, their NAT cleanup/assert block
#     (IPv4 + IPv6), their Cloudflare API auto-provisioning,
#     their systemd unit shape (Nice -15, -mtu, NAT ExecStartPre)
# What integration changed (plumbing only, no behaviour change):
#   * config lives in THIS panel's settings.json (keys: ns,
#     slowdns_mtu, slowdns_resolver, slowdns_target) and keys in
#     $RAGNAR_DIR/slowdns/; the other panel's files in
#     /etc/vps-panel/slowdns/ are mirrored on every run so both
#     layouts always agree (same keypair everywhere).
#   * their sshd_config rewrite step is NOT run here - this panel
#     manages its SSH config itself (both target boxes already carry
#     the same effective values from the verbatim install).
#   * default MTU is 1232 (their fast default). Do NOT raise it
#     blindly: the server -mtu is also the minimum EDNS payload size
#     demanded from requesters, and a real carrier path was measured
#     advertising 1395 bytes - MTU 1400 made the server FORMERR-reject
#     the app's own requests and sessions dropped every minute
#     (box 2 journal, 2026-11-13). 1400 stays available in the menu
#     for paths that can carry it.
#
# Usage: slowdns-setup.sh [NS] [CF_TOKEN] [MTU] [RESOLVER] [TARGET]
# (same argument order as the other panel's ragnar-slowdns-setup;
# empty arguments keep the values stored in settings.json)
# =====================================================================
set -uo pipefail

BASE="${RAGNAR_DIR:-/etc/ragnar}"
SD_DIR="$BASE/slowdns"
THEIR_DIR="/etc/vps-panel/slowdns"
SETTINGS="$BASE/settings.json"
BIN=/usr/local/bin/dnstt-server
MARKER="$SD_DIR/.turbo_kcp_patched"
BUILD_LOG=/tmp/ragnar-slowdns-build.log
mkdir -p "$SD_DIR" "$THEIR_DIR"

say() { echo "[slowdns-setup] $*"; }

get_setting() { # key default
    python3 - "$SETTINGS" "$1" "$2" <<'PY'
import json, os, sys
p, key, default = sys.argv[1], sys.argv[2], sys.argv[3]
s = json.load(open(p)) if os.path.exists(p) else {}
v = s.get(key)
print(default if v is None or v == "" else v)
PY
}

store_settings() { # ns mtu resolver target - empty keeps the old value
    python3 - "$SETTINGS" "$1" "$2" "$3" "$4" <<'PY'
import json, os, sys
p = sys.argv[1]
s = json.load(open(p)) if os.path.exists(p) else {}
keys = ("ns", "slowdns_mtu", "slowdns_resolver", "slowdns_target")
for key, val in zip(keys, sys.argv[2:]):
    if val:
        s[key] = val if key in ("ns", "slowdns_resolver") else int(val)
json.dump(s, open(p, "w"), indent=2)
PY
}

# Adopt the other panel's keypair if it exists and ours does not
# (keeps the live SlowDNS identity across the integration).
for f in server.key server.pub; do
    if [ ! -s "$SD_DIR/$f" ] && [ -s "$THEIR_DIR/$f" ]; then
        cp "$THEIR_DIR/$f" "$SD_DIR/$f"
    fi
done

CF_TOKEN="${2:-}"
store_settings "${1:-}" "${3:-}" "${4:-}" "${5:-}"
NS=$(get_setting ns "")
MTU=$(get_setting slowdns_mtu 1232)
RESOLVER=$(get_setting slowdns_resolver 1.1.1.1)
TARGET=$(get_setting slowdns_target 22)

# ---------------------------------------------------------------------
# 1. Kernel UDP buffers (their step 1; the maximums are only ever
#    raised here, never lowered - this panel's sysctl file sets 64 MB)
# ---------------------------------------------------------------------
sysctl -w net.core.rmem_default=16777216 >/dev/null 2>&1 || true
sysctl -w net.core.wmem_default=16777216 >/dev/null 2>&1 || true
for k in net.core.rmem_max net.core.wmem_max; do
    cur=$(sysctl -n "$k" 2>/dev/null || echo 0)
    if [ "${cur:-0}" -lt 33554432 ]; then
        sysctl -w "$k=33554432" >/dev/null 2>&1 || true
    fi
done
sysctl -w net.core.netdev_max_backlog=16384 >/dev/null 2>&1 || true

# ---------------------------------------------------------------------
# Go toolchain (dnstt needs Go >= 1.21)
# ---------------------------------------------------------------------
go_is_new_enough() {
    [ -n "$1" ] || return 1
    local maj min
    maj=$("$1" version 2>/dev/null | sed -E 's/.*go([0-9]+)\.([0-9]+).*/\1/')
    min=$("$1" version 2>/dev/null | sed -E 's/.*go([0-9]+)\.([0-9]+).*/\2/')
    [ "${maj:-0}" -gt 1 ] || { [ "${maj:-0}" -eq 1 ] && [ "${min:-0}" -ge 21 ]; }
}

ensure_go() {
    : >>"$BUILD_LOG"
    local go_bin ga
    go_bin=$(command -v go || true)
    if ! go_is_new_enough "$go_bin" && [ -x /usr/local/go-1.22/bin/go ]; then
        go_bin=/usr/local/go-1.22/bin/go
    fi
    if ! go_is_new_enough "$go_bin"; then
        command -v git >/dev/null 2>&1 || \
            apt-get install -y -q git >>"$BUILD_LOG" 2>&1 || true
        apt-get install -y -q golang-go >>"$BUILD_LOG" 2>&1 || true
        go_bin=$(command -v go || true)
    fi
    if ! go_is_new_enough "$go_bin"; then
        case "$(uname -m)" in aarch64|arm64) ga=arm64 ;; *) ga=amd64 ;; esac
        if wget -q "https://go.dev/dl/go1.22.12.linux-${ga}.tar.gz" \
                -O /tmp/go.tgz >>"$BUILD_LOG" 2>&1 && \
           rm -rf /usr/local/go-1.22 /usr/local/go && \
           tar -C /usr/local -xzf /tmp/go.tgz >>"$BUILD_LOG" 2>&1 && \
           mv /usr/local/go /usr/local/go-1.22; then
            go_bin=/usr/local/go-1.22/bin/go
        fi
        rm -f /tmp/go.tgz
    fi
    go_is_new_enough "$go_bin" && { echo "$go_bin"; return 0; }
    return 1
}

# ---------------------------------------------------------------------
# 2. Build the turbo-patched dnstt-server (their patch, verbatim sed;
#    full clone for bamsoftware - its dumb-HTTP git rejects shallow
#    clones - shallow only for the GitHub mirror)
# ---------------------------------------------------------------------
if [ ! -x "$BIN" ] || [ ! -f "$MARKER" ]; then
    say "Compiling Turbo-Optimized dnstt-server (KCP NoDelay + 1024 Window + 4MB SMUX buffer)..."
    GO_BIN=$(ensure_go) || { say "ERROR: no Go >= 1.21 toolchain available - see $BUILD_LOG"; exit 1; }
    TMP=$(mktemp -d -p /var/tmp)
    if ! git clone https://www.bamsoftware.com/git/dnstt.git "$TMP/dnstt" >>"$BUILD_LOG" 2>&1 && \
       ! git clone --depth 1 https://github.com/Mygod/dnstt.git "$TMP/dnstt" >>"$BUILD_LOG" 2>&1; then
        say "ERROR: could not clone dnstt source - see $BUILD_LOG"
        rm -rf "$TMP"; exit 1
    fi
    if [ -f "$TMP/dnstt/turbotunnel/consts.go" ]; then
        sed -i 's/QueueSize.*=.*/QueueSize = 1024/' "$TMP/dnstt/turbotunnel/consts.go" || true
    fi
    if [ -f "$TMP/dnstt/dnstt-server/main.go" ]; then
        sed -i 's/MaxStreamBuffer = .*/MaxStreamBuffer = 4 * 1024 * 1024\n\tsmuxConfig.MaxReceiveBuffer = 4 * 1024 * 1024/' "$TMP/dnstt/dnstt-server/main.go" || true
        sed -i 's/if rc := conn.SetMtu(mtu); !rc {/conn.SetNoDelay(1, 10, 2, 1)\n\t\tconn.SetWindowSize(1024, 1024)\n\t\tif rc := conn.SetMtu(mtu); !rc {/' "$TMP/dnstt/dnstt-server/main.go" || true
    fi
    if (cd "$TMP/dnstt/dnstt-server" && \
        GOPROXY=https://proxy.golang.org,direct CGO_ENABLED=0 \
        "$GO_BIN" build -ldflags="-s -w" -trimpath -o "$BIN" .) >>"$BUILD_LOG" 2>&1; then
        chmod +x "$BIN"; touch "$MARKER"
        say "Built $BIN"
    else
        say "ERROR: dnstt-server build failed - see $BUILD_LOG"
        rm -rf "$TMP"; exit 1
    fi
    rm -rf "$TMP"
fi

# ---------------------------------------------------------------------
# 3. Keypair (generate once, preserve forever) + mirror their layout
# ---------------------------------------------------------------------
if [ ! -s "$SD_DIR/server.key" ] || [ ! -s "$SD_DIR/server.pub" ]; then
    "$BIN" -gen-key -privkey-file "$SD_DIR/server.key" \
        -pubkey-file "$SD_DIR/server.pub" || {
        say "ERROR: key generation failed"; exit 1; }
    chmod 600 "$SD_DIR/server.key"
fi
cp "$SD_DIR/server.key" "$SD_DIR/server.pub" "$THEIR_DIR/" 2>/dev/null || true
chmod 600 "$THEIR_DIR/server.key" 2>/dev/null || true
[ -f "$MARKER" ] && touch "$THEIR_DIR/.turbo_kcp_patched" || true
printf '%s\n' "$NS" > "$THEIR_DIR/nameserver"
printf '%s\n' "$MTU" > "$THEIR_DIR/mtu"
printf '%s\n' "$RESOLVER" > "$THEIR_DIR/dns_resolver"
printf '%s\n' "$TARGET" > "$THEIR_DIR/target_port"
python3 - "$SETTINGS" "$SD_DIR/server.pub" <<'PY'
import json, os, sys
p = sys.argv[1]
s = json.load(open(p)) if os.path.exists(p) else {}
s["slowdns_pubkey"] = open(sys.argv[2]).read().strip()
s.pop("slowdns_kcp", None)
json.dump(s, open(p, "w"), indent=2)
PY

# ---------------------------------------------------------------------
# 4. Optional automatic Cloudflare DNS provisioning (their section 4,
#    verbatim logic: creates A record dns.<root> + NS record)
# ---------------------------------------------------------------------
ACTIVE_NS="$NS"
if [ -n "$CF_TOKEN" ] && [ -n "$ACTIVE_NS" ]; then
    VPS_IP=$(curl -fsSL4 --max-time 3 icanhazip.com 2>/dev/null || hostname -I | awk '{print $1}')
    ROOT_DOM=$(echo "${ACTIVE_NS}" | awk -F. '{if (NF>=2) print $(NF-1)"."$NF; else print $0}')
    A_HOST="dns.${ROOT_DOM}"
    echo "Configuring Cloudflare DNS records for SlowDNS: ${ACTIVE_NS} -> ${A_HOST} (${VPS_IP})..."
    ZONE_ID=$(curl -fsSL -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4/zones?name=${ROOT_DOM}" 2>/dev/null | jq -r '.result[0].id // empty' || true)
    if [ -n "${ZONE_ID}" ]; then
        OLD_A=$(curl -fsSL -H "Authorization: Bearer ${CF_TOKEN}" \
            "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=A&name=${A_HOST}" 2>/dev/null | jq -r '.result[0].id // empty' || true)
        [ -n "${OLD_A}" ] && curl -fsSL -X DELETE -H "Authorization: Bearer ${CF_TOKEN}" \
            "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${OLD_A}" >/dev/null 2>&1 || true
        curl -fsSL -X POST -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
            "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
            --data "{\"type\":\"A\",\"name\":\"${A_HOST}\",\"content\":\"${VPS_IP}\",\"ttl\":1,\"proxied\":false}" >/dev/null 2>&1 || true
        OLD_NS=$(curl -fsSL -H "Authorization: Bearer ${CF_TOKEN}" \
            "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=NS&name=${ACTIVE_NS}" 2>/dev/null | jq -r '.result[0].id // empty' || true)
        [ -n "${OLD_NS}" ] && curl -fsSL -X DELETE -H "Authorization: Bearer ${CF_TOKEN}" \
            "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records/${OLD_NS}" >/dev/null 2>&1 || true
        curl -fsSL -X POST -H "Authorization: Bearer ${CF_TOKEN}" -H "Content-Type: application/json" \
            "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records" \
            --data "{\"type\":\"NS\",\"name\":\"${ACTIVE_NS}\",\"content\":\"${A_HOST}\",\"ttl\":1}" >/dev/null 2>&1 || true
        echo "Cloudflare DNS records created: A (${A_HOST} -> ${VPS_IP}) and NS (${ACTIVE_NS} -> ${A_HOST})!"
    else
        echo "Warning: Could not find Cloudflare Zone for ${ROOT_DOM}. Verify your API Token has Zone:Read and DNS:Edit."
    fi
fi

# ---------------------------------------------------------------------
# 5. UDP 53 -> 5300 redirection (their section 5, verbatim: clean up
#    every older redirect variant, keep local 127.0.0.0/8 DNS working,
#    IPv4 + IPv6, ufw allows)
# ---------------------------------------------------------------------
iptables -t nat -D PREROUTING -p udp --dport 5300 -j REDIRECT --to-ports 53 2>/dev/null || true
iptables -t nat -D PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true
iptables -t nat -D PREROUTING ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true
MAIN_IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5}' | head -n1)
if [ -n "${MAIN_IFACE}" ]; then
    iptables -t nat -D PREROUTING -i "${MAIN_IFACE}" -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true
fi
iptables -I INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -I INPUT -p udp --dport 5300 -j ACCEPT 2>/dev/null || true
iptables -t nat -I PREROUTING ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true

ip6tables -t nat -D PREROUTING -p udp --dport 5300 -j REDIRECT --to-ports 53 2>/dev/null || true
ip6tables -t nat -D PREROUTING ! -d ::1/128 -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true
ip6tables -I INPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
ip6tables -I INPUT -p udp --dport 5300 -j ACCEPT 2>/dev/null || true
ip6tables -t nat -I PREROUTING ! -d ::1/128 -p udp --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true

if command -v ufw >/dev/null 2>&1; then
    ufw allow 53/udp >/dev/null 2>&1 || true
    ufw allow 5300/udp >/dev/null 2>&1 || true
fi

if [ -z "$NS" ]; then
    say "Binary and keys are ready, but no nameserver is set."
    say "Set it in the panel menu (SLOWDNS) to start the service."
    exit 0
fi

# Stop MasterDnsVPN if it was previously occupying UDP port 53 (theirs)
systemctl stop masterdnsvpn 2>/dev/null || true
systemctl disable masterdnsvpn 2>/dev/null || true

# ---------------------------------------------------------------------
# 6. systemd unit (their shape, this panel's key path)
# ---------------------------------------------------------------------
cat > /etc/systemd/system/slowdns.service <<EOF
[Unit]
Description=Ragnar Turbo SlowDNS (DNSTT) Server (UDP 53 -> 5300 -> 127.0.0.1:${TARGET}, MTU ${MTU})
After=network.target ssh.service dropbear.service

[Service]
Type=simple
Nice=-15
LimitNOFILE=1000000
ExecStartPre=-/sbin/iptables -I INPUT -p udp --dport 53 -j ACCEPT
ExecStartPre=-/sbin/iptables -I INPUT -p udp --dport 5300 -j ACCEPT
ExecStartPre=-/sbin/iptables -t nat -D PREROUTING ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-ports 5300
ExecStartPre=-/sbin/iptables -t nat -I PREROUTING ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to-ports 5300
ExecStart=$BIN -udp :5300 -mtu ${MTU} -privkey-file $SD_DIR/server.key ${NS} 127.0.0.1:${TARGET}
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable slowdns >/dev/null 2>&1 || true
systemctl restart slowdns
say "SlowDNS running: NS ${NS}, MTU ${MTU}, resolver ${RESOLVER}, target 127.0.0.1:${TARGET}"
