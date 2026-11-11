#!/bin/bash
# Ragnar VPS Management Panel - uninstaller
# Removes the panel, its services and its NAT rules. Panel-created Linux
# users are listed and removed only after a separate confirmation.
set -u
BASE="/etc/ragnar"
[ "$(id -u)" = 0 ] || { echo "Run as root"; exit 1; }
echo "This removes Ragnar Panel services, configs and firewall rules."
read -rp "Continue? [y/N] " a; [ "$a" = y ] || exit 0

for svc in ragnar-check.timer ragnar-watchdog.timer xray sing-box zivpn \
           udp-custom badvpn-udpgw udpgw slowdns ragnar-wsproxy ragnar-landing cloudflared; do
    systemctl disable --now "$svc" 2>/dev/null || true
    rm -f "/etc/systemd/system/$svc.service" "/etc/systemd/system/$svc.timer"
done
systemctl daemon-reload

# HAProxy was the front door - restore the pre-Ragnar config if we kept one
if [ -f /etc/haproxy/haproxy.cfg.bak-ragnar ]; then
    mv /etc/haproxy/haproxy.cfg.bak-ragnar /etc/haproxy/haproxy.cfg
    systemctl restart haproxy 2>/dev/null || true
fi

# Panel NAT rules
iptables -t nat -D PREROUTING -p udp --dport 6000:19999 -j REDIRECT --to-ports 5667 2>/dev/null || true
iptables -t nat -D PREROUTING -p udp --dport 20000:65535 -j REDIRECT --to-ports 36712 2>/dev/null || true
iptables -t nat -D PREROUTING -p tcp --dport 8446 -j REDIRECT --to-ports 10006 2>/dev/null || true
for proto in udp tcp; do
    iptables -t nat -D PREROUTING -p $proto --dport 53 -j REDIRECT --to-ports 5300 2>/dev/null || true
done
netfilter-persistent save >/dev/null 2>&1 || true

rm -f /etc/sysctl.d/99-ragnar-tuning.conf /etc/ssh/sshd_config.d/60-ragnar.conf
rm -f /usr/local/bin/menu /usr/local/bin/ragnar /usr/local/bin/zivpn \
      /usr/local/bin/udp-custom /usr/local/bin/sldns-server /usr/local/bin/udpgw \
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
