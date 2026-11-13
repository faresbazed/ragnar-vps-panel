#!/bin/bash
# Ragnar VPS Management Panel - uninstaller
# Removes the panel, its services and its NAT rules. Panel-created Linux
# users are listed and removed only after a separate confirmation.
set -u
BASE="/etc/ragnar"
[ "$(id -u)" = 0 ] || { echo "Run as root"; exit 1; }
echo "This removes Ragnar Panel services, configs and firewall rules."
read -rp "Continue? [y/N] " a; [ "$a" = y ] || exit 0

# HAProxy FIRST: it is the front door. Stopping the backends while it is
# still running leaves it logging "backend has no server available!" at
# alert level forever, which journald broadcasts to every terminal.
systemctl disable --now haproxy 2>/dev/null || true

for svc in ragnar-check.timer ragnar-watchdog.timer ragnar-check ragnar-watchdog \
           xray sing-box zivpn udp-custom badvpn-udpgw udpgw slowdns \
           ragnar-wsproxy ragnar-landing cloudflared ragnar-web; do
    systemctl disable --now "$svc" 2>/dev/null || true
done
# Remove unit files by base name (the old loop built names like
# "ragnar-check.timer.service", which never exist, and left files behind).
for u in ragnar-check ragnar-watchdog xray sing-box zivpn udp-custom \
         badvpn-udpgw udpgw slowdns ragnar-wsproxy ragnar-landing cloudflared \
         ragnar-web; do
    rm -f "/etc/systemd/system/$u.service" "/etc/systemd/system/$u.timer"
done
systemctl daemon-reload
systemctl reset-failed 2>/dev/null || true

# HAProxy config: restore the pre-Ragnar config if we kept one; otherwise
# HAProxy only existed for the panel - leave a minimal stock config in
# place and the service disabled, never the Ragnar routing.
if [ -f /etc/haproxy/haproxy.cfg.bak-ragnar ]; then
    mv /etc/haproxy/haproxy.cfg.bak-ragnar /etc/haproxy/haproxy.cfg
    systemctl enable --now haproxy 2>/dev/null || true
elif [ -d /etc/haproxy ]; then
    cat > /etc/haproxy/haproxy.cfg <<'CFG'
global
    log /dev/log local0
    maxconn 2048
    daemon
defaults
    log global
    mode http
    timeout connect 5s
    timeout client 50s
    timeout server 50s
CFG
fi

# Panel NAT rules: delete by the exact spec found in the chain, so extra
# match clauses on a rule (e.g. "! -d 127.0.0.0/8" added by other tools)
# cannot make a rule survive the uninstall.
for target in 5300 5667 36712 10006; do
    while spec=$(iptables -t nat -S PREROUTING 2>/dev/null | grep -E "REDIRECT --to-ports ${target}$" | head -1); [ -n "$spec" ]; do
        iptables -t nat -D PREROUTING ${spec#-A PREROUTING } 2>/dev/null || break
    done
done
netfilter-persistent save >/dev/null 2>&1 || true

rm -f /etc/sysctl.d/99-ragnar-tuning.conf /etc/ssh/sshd_config.d/60-ragnar.conf
rm -f /usr/local/bin/menu /usr/local/bin/ragnar /usr/local/bin/zivpn \
      /usr/local/bin/udp-custom /usr/local/bin/dnstt-server /usr/local/bin/sldns-server /usr/local/bin/sldns-server-kcp /usr/local/bin/udpgw \
      /usr/local/bin/badvpn-udpgw

if [ -f "$BASE/db/ssh.json" ]; then
    echo "Panel SSH users:"
    python3 -c "import json;print('\n'.join(json.load(open('$BASE/db/ssh.json'))['users']))" 2>/dev/null
    read -rp "Delete these Linux accounts too? [y/N] " b
    if [ "$b" = y ]; then
        python3 -c "import json;print('\n'.join(json.load(open('$BASE/db/ssh.json'))['users']))" \
            | while read -r u; do userdel -r "$u" 2>/dev/null; done
    fi
fi
rm -rf "$BASE"
echo "Ragnar Panel removed. Xray / sing-box / cloudflared binaries were left"
echo "installed (they are upstream tools, remove them with their own uninstallers)."
echo "Bye - @farisbazed / https://t.me/ragnaresim"
