#!/usr/bin/env bash
# =====================================================================
# Ragnar SlowDNS setup - the dnstt-server implementation from
# faresbazed/Ragnar-VPS-Management-Panel, integrated with this panel.
#
#   * Builds /usr/local/bin/dnstt-server from bamsoftware dnstt source
#     with that panel's turbo patch (applied by sed at build time):
#       - turbotunnel QueueSize = 1024
#       - smux MaxStreamBuffer = MaxReceiveBuffer = 4 MB
#       - KCP SetNoDelay(1, 10, 2, 1) + SetWindowSize(1024, 1024)
#   * Keypair lives in $RAGNAR_DIR/slowdns/ and is generated only when
#     missing - an existing keypair (and every app profile using its
#     public key) survives the swap untouched.
#   * Writes the slowdns systemd unit (Nice -15, NAT 53 -> 5300
#     re-asserted by ExecStartPre on every start) and restarts it.
#     The unit runs: dnstt-server -udp :5300 -mtu <MTU> NS 127.0.0.1:22
#
# Usage: slowdns-setup.sh [NS] [MTU] [RESOLVER] [TARGET_PORT]
# Empty arguments keep the values in $RAGNAR_DIR/settings.json
# (keys: ns, slowdns_mtu [default 1232], slowdns_resolver [1.1.1.1],
# slowdns_target [22]).
# =====================================================================
set -uo pipefail

BASE="${RAGNAR_DIR:-/etc/ragnar}"
SD_DIR="$BASE/slowdns"
SETTINGS="$BASE/settings.json"
BIN=/usr/local/bin/dnstt-server
MARKER="$SD_DIR/.turbo_kcp_patched"
BUILD_LOG=/tmp/ragnar-slowdns-build.log
mkdir -p "$SD_DIR"

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

store_settings "${1:-}" "${2:-}" "${3:-}" "${4:-}"
NS=$(get_setting ns "")
MTU=$(get_setting slowdns_mtu 1232)
RESOLVER=$(get_setting slowdns_resolver 1.1.1.1)
TARGET=$(get_setting slowdns_target 22)

# UDP buffers (step 1 of the other panel's setup, applied at runtime).
# The dnstt server's UDP socket gets the kernel DEFAULT buffer, so the
# defaults matter as much as the maximums: 16 MB defaults keep DNS
# bursts from being dropped on lossy resolver paths. (An earlier port
# of this setup skipped these lines and SlowDNS ran on 1 MB defaults -
# noticeably slower than the other panel on the same server.) The
# maximums are only ever raised here, never lowered: this panel's
# sysctl file sets 64 MB, the other panel's runtime value is 32 MB.
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
# Go toolchain (dnstt needs Go >= 1.21; same proven detection the old
# KCP build used: system go, a previous panel toolchain, apt, tarball)
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
# Build the turbo-patched dnstt-server (the other panel's patch,
# verbatim sed expressions; clone strategy differs only because
# bamsoftware.com serves git over the dumb HTTP protocol, which
# rejects shallow clones - full clone there, shallow for the mirror)
# ---------------------------------------------------------------------
if [ ! -x "$BIN" ] || [ ! -f "$MARKER" ]; then
    say "Building turbo-patched dnstt-server (KCP NoDelay + 1024 window + 4MB smux)..."
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
# Keypair (generate once, preserve forever)
# ---------------------------------------------------------------------
if [ ! -s "$SD_DIR/server.key" ] || [ ! -s "$SD_DIR/server.pub" ]; then
    "$BIN" -gen-key -privkey-file "$SD_DIR/server.key" \
        -pubkey-file "$SD_DIR/server.pub" || {
        say "ERROR: key generation failed"; exit 1; }
    chmod 600 "$SD_DIR/server.key"
fi
python3 - "$SETTINGS" "$SD_DIR/server.pub" <<'PY'
import json, os, sys
p = sys.argv[1]
s = json.load(open(p)) if os.path.exists(p) else {}
s["slowdns_pubkey"] = open(sys.argv[2]).read().strip()
s.pop("slowdns_kcp", None)  # the old stock/turbo toggle no longer exists
json.dump(s, open(p, "w"), indent=2)
PY

if [ -z "$NS" ]; then
    say "Binary and keys are ready, but no nameserver is set."
    say "Set it in the panel menu (SLOWDNS -> SET NAMESERVER) to start the service."
    exit 0
fi

# ---------------------------------------------------------------------
# systemd unit (the other panel's shape, this panel's paths)
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
