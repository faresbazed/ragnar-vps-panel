#!/bin/bash
# =====================================================================
# Ragnar VPS Management Panel - main menu
# Telegram : @farisbazed
# Channel  : https://t.me/ragnaresim
# =====================================================================
RAGNAR_DIR="${RAGNAR_DIR:-/etc/ragnar}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="${RAGNAR_CORE:-$RAGNAR_DIR/core/ragnar.py}"
[ -f "$CORE" ] || CORE="$DIR/core/ragnar.py"
export RAGNAR_DIR

# ---- colours (matched to the reference look) -------------------------
P='\033[95m'; P2='\033[35m'; C='\033[96m'; G='\033[92m'; Y='\033[93m'
W='\033[97m'; R='\033[91m'; DIM='\033[90m'; N='\033[0m'; B='\033[1m'

bar() { # section header like the reference: purple line + yellow title
    local title="$1" line
    line=$(printf '─%.0s' $(seq 1 46))
    echo -e "${P}┌${line}┐${N}"
    printf "${P}│${N} %*s${Y}${B}%s${N}%*s ${P}│${N}\n" \
        $(( (44 - ${#title}) / 2 )) "" "$title" $(( (45 - ${#title}) / 2 )) ""
    echo -e "${P}└${line}┘${N}"
}
kv() { printf "${C}%-14s${W}: ${G}%s${N}\n" "$1" "$2"; }
opt() { printf "${P}〈${Y}%s${P}〉${W}  %s\n" "$1" "$2"; }
svc_dot() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        echo -e "${G}● ONLINE${N}"
    else
        echo -e "${R}● OFFLINE${N}"
    fi
}
svc_dot_cf() { # cloudflared only runs once a tunnel token is installed
    if systemctl is-active --quiet cloudflared 2>/dev/null; then
        echo -e "${G}● ONLINE${N}"
    elif systemctl list-unit-files cloudflared.service >/dev/null 2>&1 \
         && systemctl list-unit-files cloudflared.service | grep -q cloudflared; then
        echo -e "${R}● OFFLINE${N}"
    else
        echo -e "${Y}● NO TUNNEL${N}"
    fi
}
pause() { read -rp "Press Enter to continue..." _; }

bandwidth_lines() { # TODAY / MONTH measured traffic, one line each
    python3 "$CORE" bandwidth 2>/dev/null | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    d = {}
def line(label, p):
    if not p:
        return "%-6s n/a" % label
    return "%-6s RX %9s  TX %9s  TOTAL %9s" % (
        label, p["rx_f"], p["tx_f"], p["total_f"])
print(line("TODAY", d.get("today")))
print(line("MONTH", d.get("month")))
src = d.get("source")
if src and src != "vnstat":
    print("(bandwidth source: %s)" % src)
' | while IFS= read -r l; do echo -e "${C}$l${N}"; done
}

human() { numfmt --to=iec-i --suffix=B "$1" 2>/dev/null || echo "$1 B"; }

server_ip() {
    local f="$RAGNAR_DIR/host"
    [ -s "$f" ] && cat "$f" && return
    curl -s4 --max-time 4 https://api.ipify.org || hostname -I | awk '{print $1}'
}
server_isp() {
    curl -s --max-time 4 "https://ipinfo.io/org" 2>/dev/null | sed 's/^AS[0-9]* //' \
        || echo "Unknown"
}

print_header() {
    clear
    local ip isp os up cpu ram disk now
    ip=$(server_ip); isp=$(server_isp)
    os=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
    up=$(uptime -p 2>/dev/null | sed 's/^up //')
    cpu=$(top -bn1 2>/dev/null | awk '/Cpu/ {print 100-$8"%"}' | head -1)
    ram=$(free -m | awk '/Mem:/ {printf "%sMB / %sMB", $3, $2}')
    disk=$(df -h / | awk 'NR==2 {printf "%s/%s", $3, $2}')
    now=$(date '+%d-%m-%Y %T')
    echo -e "${P2}${B}   RAGNAR VPS MANAGEMENT PANEL${N}"
    echo -e "${C}   Telegram : ${W}@farisbazed${C}   Channel : ${W}https://t.me/ragnaresim${N}"
    bar "SERVER INFO"
    kv "IP" "$ip";        kv "ISP" "$isp";       kv "OS" "$os"
    kv "UPTIME" "$up";    kv "CPU USAGE" "${cpu:-n/a}"
    kv "RAM USAGE" "$ram"; kv "DISK USAGE" "$disk"; kv "SERVER TIME" "$now"
    # bandwidth: measured totals via the core (vnstat --json for the WAN
    # interface, matched by date - never positional fields; kernel
    # counters since boot as a labelled fallback)
    bar "BANDWIDTH"
    bandwidth_lines
    # user stats
    local stats total online
    stats=$(python3 "$CORE" stats 2>/dev/null)
    get() { echo "$stats" | grep -o "\"$1\": [0-9]*" | grep -o '[0-9]*$'; }
    total=$(get total); online=$(python3 "$CORE" online 2>/dev/null | grep -o '"online": [0-9]*' | grep -o '[0-9]*$')
    bar "USER STATS"
    printf "${C}%-8s${W}: ${G}%-6s${C}%-8s${W}: ${G}%-6s${C}%-9s${W}: ${G}%s${N}\n" \
        "VMESS" "$(get vmess)" "VLESS" "$(get vless)" "TROJAN" "$(get trojan)"
    printf "${C}%-8s${W}: ${G}%-6s${C}%-8s${W}: ${G}%-6s${C}%-9s${W}: ${G}%s${N}\n" \
        "SSWS" "$(get ssws)" "SSH" "$(get ssh)" "ZIVPN" "$(get zivpn)"
    printf "${C}%-8s${W}: ${G}%-6s${C}%-8s${W}: ${G}%s${N}\n" \
        "TOTAL" "${total:-0}" "ONLINE" "${online:-0}"
    bar "SERVICE"
    printf "${C}%-13s${W}: %-22s${C}%-13s${W}: %s${N}\n" "XRAY" "$(svc_dot xray)" "HAPROXY" "$(svc_dot haproxy)"
    printf "${C}%-13s${W}: %-22s${C}%-13s${W}: %s${N}\n" "DROPBEAR" "$(svc_dot dropbear)" "SING-BOX" "$(svc_dot sing-box)"
    printf "${C}%-13s${W}: %-22s${C}%-13s${W}: %s${N}\n" "UDP CUSTOM" "$(svc_dot udp-custom)" "UDP ZIVPN" "$(svc_dot zivpn)"
    printf "${C}%-13s${W}: %-22s${C}%-13s${W}: %s${N}\n" "SSH WS" "$(svc_dot ragnar-wsproxy)" "WSS / SSL" "$(svc_dot haproxy)"
    printf "${C}%-13s${W}: %-22s${C}%-13s${W}: %s${N}\n" "SLOWDNS" "$(svc_dot slowdns)" "BADVPN" "$(svc_dot badvpn-udpgw)"
    printf "${C}%-13s${W}: %-22s${C}%-13s${W}: %s${N}\n" "CLOUDFLARED" "$(svc_dot_cf)" "" ""
}

main_menu() {
    bar "MAIN MENU"
    echo -e "${P}${B}   USERS${N}"
    opt 1 "SSH & SSL"
    opt 2 "XRAY (ALL PROTOCOLS)"
    opt 3 "UDP ZIVPN"
    opt 4 "UDP CUSTOM"
    echo -e "${P}${B}   SERVICES${N}"
    opt 5 "SLOWDNS"
    opt 6 "CLOUDFLARED"
    opt 7 "WEB PANEL"
    opt 8 "STATUS"
    opt 9 "TOOLS"
    echo -e "${P}${B}   SYSTEM${N}"
    opt 10 "CLEAR RAM"
    opt 11 "REBOOT VPS"
    opt 12 "UNINSTALL"
    opt x "EXIT"
    echo -e "${DIM}   Panel by @farisbazed - https://t.me/ragnaresim${N}"
}

# ---------------------------------------------------------------------
# SSH submenu
# ---------------------------------------------------------------------
ssh_create() {
    local u p d q i
    read -rp "Username        : " u
    read -rp "Password        : " p
    read -rp "Duration (days) : " d
    read -rp "Quota GB (0=inf): " q
    read -rp "IP limit (0=inf): " i
    python3 "$CORE" ssh-add "$u" "$p" "${d:-30}" "${q:-0}" "${i:-0}"
    pause
}
ssh_list() { python3 "$CORE" ssh-list; pause; }
ssh_info() { local u; read -rp "Username: " u; python3 "$CORE" ssh-info "$u"; pause; }
ssh_edit() {
    local u what
    read -rp "Username to edit: " u
    echo "1) Renew/extend days"
    echo "2) Set quota GB"
    echo "3) Set IP limit"
    echo "4) Change password"
    echo "5) Enable"
    echo "6) Disable"
    read -rp "Choice: " what
    case $what in
        1) read -rp "Add how many days? " v; python3 "$CORE" ssh-edit "$u" --days "$v" --extend ;;
        2) read -rp "New quota GB (0=inf): " v; python3 "$CORE" ssh-edit "$u" --quota-gb "$v" ;;
        3) read -rp "New IP limit (0=inf): " v; python3 "$CORE" ssh-edit "$u" --ip-limit "$v" ;;
        4) read -rp "New password: " v; python3 "$CORE" ssh-edit "$u" --password "$v" ;;
        5) python3 "$CORE" ssh-edit "$u" --enable ;;
        6) python3 "$CORE" ssh-edit "$u" --disable ;;
    esac
    pause
}
ssh_del() { local u; read -rp "Username to DELETE: " u
    read -rp "Are you sure? [y/N] " a; [ "$a" = y ] && python3 "$CORE" ssh-del "$u"; pause; }
ssh_menu() {
    while true; do
        print_header; bar "SSH & SSL"
        opt 1 "CREATE USER"
        opt 2 "LIST USERS"
        opt 3 "EDIT / RENEW"
        opt 4 "DELETE USER"
        opt 5 "USER INFO"
        opt 0 "BACK"
        read -rp "Choice: " c
        case $c in
            1) ssh_create ;; 2) ssh_list ;; 3) ssh_edit ;;
            4) ssh_del ;; 5) ssh_info ;; 0) return ;;
        esac
    done
}

# ---------------------------------------------------------------------
# Xray submenu (one user -> VLESS+VMESS+Trojan+SSWS+AnyTLS together)
# ---------------------------------------------------------------------
xray_create() {
    local u d q i
    read -rp "Username        : " u
    read -rp "Duration (days) : " d
    read -rp "Quota GB (0=inf): " q
    read -rp "IP limit (0=inf): " i
    python3 "$CORE" xray-add "$u" "${d:-30}" "${q:-0}" "${i:-0}"
    echo -e "${G}All protocols created together. Links above include direct 80/443 and Cloudflare 80/443.${N}"
    pause
}
xray_links() {
    local u; read -rp "Username: " u
    python3 "$CORE" xray-links "$u"
    pause
}
xray_info() { local u; read -rp "Username: " u; python3 "$CORE" xray-info "$u"; pause; }
xray_copy_one() {
    local u proto
    read -rp "Username: " u
    read -rp "Protocol (VLESS/VMESS/TROJAN/SSWS/ANYTLS): " proto
    python3 "$CORE" xray-links "$u" | grep -i "^$proto" || python3 "$CORE" xray-links "$u"
    pause
}
xray_edit() {
    local u what
    read -rp "Username to edit: " u
    echo "1) Renew/extend days"
    echo "2) Set quota GB"
    echo "3) Set IP limit"
    echo "4) Enable"
    echo "5) Disable"
    read -rp "Choice: " what
    case $what in
        1) read -rp "Add how many days? " v; python3 "$CORE" xray-edit "$u" --days "$v" --extend ;;
        2) read -rp "New quota GB (0=inf): " v; python3 "$CORE" xray-edit "$u" --quota-gb "$v" ;;
        3) read -rp "New IP limit (0=inf): " v; python3 "$CORE" xray-edit "$u" --ip-limit "$v" ;;
        4) python3 "$CORE" xray-edit "$u" --enable ;;
        5) python3 "$CORE" xray-edit "$u" --disable ;;
    esac
    pause
}
xray_del() { local u; read -rp "Username to DELETE: " u
    read -rp "Are you sure? [y/N] " a; [ "$a" = y ] && python3 "$CORE" xray-del "$u"; pause; }
xray_menu() {
    while true; do
        print_header; bar "XRAY - ALL PROTOCOLS"
        opt 1 "CREATE USER"
        opt 2 "LIST USERS"
        opt 3 "EDIT / RENEW"
        opt 4 "DELETE USER"
        opt 5 "USER INFO"
        opt 6 "SHOW LINKS"
        opt 7 "COPY ONE LINK"
        opt 0 "BACK"
        read -rp "Choice: " c
        case $c in
            1) xray_create ;; 2) python3 "$CORE" xray-list; pause ;;
            3) xray_edit ;; 4) xray_del ;; 5) xray_info ;;
            6) xray_links ;; 7) xray_copy_one ;; 0) return ;;
        esac
    done
}

# ---------------------------------------------------------------------
# UDP ZIVPN / UDP Custom / SlowDNS / Cloudflared
# ---------------------------------------------------------------------
zivpn_menu() {
    while true; do
        print_header; bar "UDP ZIVPN (port 5667)"
        opt 1 "CREATE USER"
        opt 2 "LIST USERS"
        opt 3 "DELETE USER"
        opt 4 "SERVER INFO"
        opt 5 "RESTART"
        opt 0 "BACK"
        read -rp "Choice: " c
        case $c in
            1) read -rp "Name: " u; read -rp "Password: " p; read -rp "Days: " d
               python3 "$CORE" zivpn-add "$u" "$p" "${d:-30}"; pause ;;
            2) python3 "$CORE" zivpn-list; pause ;;
            3) read -rp "Name: " u; python3 "$CORE" zivpn-del "$u"; pause ;;
            4) echo "Server : $(server_ip):5667 (UDP, range 6000-19999 redirected)"
               echo "Obfs   : zivpn   -   passwords are per-user, see list"; pause ;;
            5) systemctl restart zivpn; echo restarted; pause ;;
            0) return ;;
        esac
    done
}
udpcustom_menu() {
    while true; do
        print_header; bar "UDP CUSTOM"
        echo "UDP Custom uses your SSH users (same username/password)."
        echo "Ports  : UDP 1-65535 (excluding panel ports) -> udp-custom :36712"
        echo "Gateway: badvpn-udpgw 127.0.0.1:7300"
        opt 1 "RESTART"
        opt 2 "STATUS LOG"
        opt 0 "BACK"
        read -rp "Choice: " c
        case $c in
            1) systemctl restart udp-custom badvpn-udpgw; echo restarted; pause ;;
            2) systemctl --no-pager status udp-custom | head -20; pause ;;
            0) return ;;
        esac
    done
}
slowdns_menu() {
    while true; do
        print_header; bar "SLOWDNS (DNSTT)"
        local ns pub
        ns=$(python3 -c "import json;print(json.load(open('$RAGNAR_DIR/settings.json')).get('ns',''))" 2>/dev/null)
        pub=$(python3 -c "import json;print(json.load(open('$RAGNAR_DIR/settings.json')).get('slowdns_pubkey',''))" 2>/dev/null)
        echo "Nameserver : ${ns:-not set}"
        echo "Public key : ${pub:-not set}"
        echo "Endpoint   : UDP/TCP 53 -> dnstt 127.0.0.1:5300 -> SSH 22"
        local kcp kcp_txt
        kcp=$(python3 -c "import json;print(json.load(open('$RAGNAR_DIR/settings.json')).get('slowdns_kcp',False))" 2>/dev/null)
        if [ ! -x /usr/local/bin/sldns-server-kcp ]; then kcp_txt="NOT INSTALLED (re-run install.sh)"
        elif [ "$kcp" = "True" ]; then kcp_txt="ON (turbo binary, KCP nodelay + window 8192)"
        else kcp_txt="OFF (stock binary)"; fi
        echo "KCP Turbo  : $kcp_txt"
        opt 1 "RESTART"
        opt 2 "SET NAMESERVER"
        opt 3 "TOGGLE KCP TURBO"
        opt 0 "BACK"
        read -rp "Choice: " c
        case $c in
            1) systemctl restart slowdns; echo restarted; pause ;;
            3) if [ ! -x /usr/local/bin/sldns-server-kcp ] && [ "$kcp" != "True" ]; then
                   echo "Turbo binary not installed - re-run install.sh to build it"; pause
               else
                   local newbin newflag
                   if [ "$kcp" = "True" ]; then newbin=/usr/local/bin/sldns-server; newflag=False
                   else newbin=/usr/local/bin/sldns-server-kcp; newflag=True; fi
                   sed -i "s|ExecStart=/usr/local/bin/sldns-server[a-z-]*|ExecStart=$newbin|" /etc/systemd/system/slowdns.service
                   python3 - "$newflag" <<'PY'
import json,sys,os
p=os.path.join(os.environ.get("RAGNAR_DIR","/etc/ragnar"),"settings.json")
s=json.load(open(p)) if os.path.exists(p) else {}
s["slowdns_kcp"]=sys.argv[1]=="True"
json.dump(s,open(p,"w"),indent=2)
PY
                   systemctl daemon-reload; systemctl restart slowdns
                   echo "KCP Turbo now: $newflag (binary: $newbin)"; pause
               fi ;;
            2) read -rp "Nameserver (e.g. ns.yourdomain.com): " v
               python3 - "$v" <<'PY'
import json,sys,os
p=os.path.join(os.environ.get("RAGNAR_DIR","/etc/ragnar"),"settings.json")
s=json.load(open(p)) if os.path.exists(p) else {}
s["ns"]=sys.argv[1]
json.dump(s,open(p,"w"),indent=2)
print("saved - point an NS record for it at this VPS, then restart SlowDNS")
PY
               pause ;;
            0) return ;;
        esac
    done
}
cloudflared_menu() {
    while true; do
        print_header; bar "CLOUDFLARED"
        echo "Cloudflare carries the WS protocols (VLESS/VMESS/Trojan/SSWS/SSH-WS)"
        echo "on ports 80 and 443. AnyTLS is raw TLS and stays direct (CF proxy"
        echo "cannot carry it - that is a Cloudflare limit, not a panel limit)."
        opt 1 "SET DOMAIN (for TLS + CF links)"
        opt 2 "SET CF HOSTNAME USED IN LINKS"
        opt 3 "INSTALL TUNNEL TOKEN & ENABLE SERVICE"
        opt 4 "QUICK TUNNEL (trycloudflare, temp hostname)"
        opt 0 "BACK"
        read -rp "Choice: " c
        case $c in
            1) read -rp "Domain: " v; echo "$v" > "$RAGNAR_DIR/domain"
               python3 "$CORE" gen-configs; echo "saved"; pause ;;
            2) read -rp "CF hostname: " v
               python3 - "$v" <<'PY'
import json,sys,os
p=os.path.join(os.environ.get("RAGNAR_DIR","/etc/ragnar"),"settings.json")
s=json.load(open(p)) if os.path.exists(p) else {}
s["cf_host"]=sys.argv[1]
json.dump(s,open(p,"w"),indent=2)
print("saved")
PY
               pause ;;
            3) read -rp "Tunnel token: " v
               systemctl stop cloudflared 2>/dev/null
               cloudflared service install "$v" && systemctl enable --now cloudflared
               pause ;;
            4) echo "Starting quick tunnel - the https hostname appears in the log."
               echo "Point it at http://127.0.0.1:80 (the HAProxy front door)."
               timeout 10 cloudflared tunnel --url http://127.0.0.1:80 2>&1 | head -30
               pause ;;
            0) return ;;
        esac
    done
}

# ---------------------------------------------------------------------
# Web panel (3x-ui style, HTTPS on port 2053)
# ---------------------------------------------------------------------
webpanel_menu() {
    while true; do
        print_header; bar "WEB PANEL"
        local dom url
        dom=$(python3 -c "import json;print(json.load(open('$RAGNAR_DIR/settings.json')).get('domain',''))" 2>/dev/null)
        [ -z "$dom" ] && dom=$(server_ip)
        url="https://$dom/panel"
        echo "URL     : $url"
        printf "Service : %s\n" "$(svc_dot ragnar-web)"
        echo "Log in with the admin username/password (set at install;"
        echo "reset it below if you lost it)."
        opt 1 "SERVICE STATUS"
        opt 2 "RESET ADMIN PASSWORD"
        opt 3 "RESTART WEB PANEL"
        opt 4 "STOP / START WEB PANEL"
        opt 0 "BACK"
        read -rp "Choice: " c
        case $c in
            1) echo "Open: $url"; systemctl --no-pager status ragnar-web | head -12; pause ;;
            2) python3 "$RAGNAR_DIR/web/webpanel.py" --reset-password; pause ;;
            3) systemctl restart ragnar-web; echo restarted; pause ;;
            4) if systemctl is-active --quiet ragnar-web; then
                   systemctl stop ragnar-web; echo stopped
               else systemctl start ragnar-web; echo started; fi; pause ;;
            0) return ;;
        esac
    done
}

# ---------------------------------------------------------------------
# Tools / status
# ---------------------------------------------------------------------
tools_menu() {
    while true; do
        print_header; bar "TOOLS"
        opt 1 "RESTART ALL SERVICES"
        opt 2 "BACKUP USERS (tar.gz)"
        opt 3 "RUN LIMIT CHECKER"
        opt 4 "SPEED TEST"
        opt 5 "LISTENING PORTS"
        opt 0 "BACK"
        read -rp "Choice: " c
        case $c in
            1) systemctl restart haproxy xray sing-box ragnar-wsproxy dropbear \
                   zivpn udp-custom badvpn-udpgw slowdns ragnar-web 2>/dev/null; echo done; pause ;;
            2) local f="/root/ragnar-backup-$(date +%F-%H%M).tar.gz"
               tar -czf "$f" -C "$RAGNAR_DIR" db settings.json 2>/dev/null && echo "Saved: $f"; pause ;;
            3) /usr/local/bin/ragnar-check --apply 2>/dev/null || \
               python3 "$RAGNAR_DIR/core/checker.py" --apply; pause ;;
            4) curl -s -o /dev/null -w "Download: %{speed_download} B/s\n" \
                   --max-time 15 https://speed.cloudflare.com/__down?bytes=25000000; pause ;;
            5) ss -tulnp | grep -E ':(80|443|22|109|5667|36712|53|7300|8446)\b'; pause ;;
            0) return ;;
        esac
    done
}
status_page() {
    print_header; bar "STATUS"
    for s in haproxy xray sing-box ragnar-wsproxy dropbear ssh zivpn udp-custom \
             badvpn-udpgw slowdns cloudflared ragnar-web ragnar-watchdog.timer; do
        printf "${C}%-24s${W}: %s${N}\n" "$s" "$(svc_dot $s)"
    done
    echo; bar "BANDWIDTH"; bandwidth_lines
    echo; ss -tulnp 2>/dev/null | grep -E ':(80|443|22|109|5667|36712|53|8446)\b' || true
    pause
}

# ---------------------------------------------------------------------
if [ "${RAGNAR_PREVIEW:-}" = "1" ]; then
    print_header; main_menu; exit 0
fi

while true; do
    print_header; main_menu
    read -rp "Select menu: " opt
    case $opt in
        1) ssh_menu ;;
        2) xray_menu ;;
        3) zivpn_menu ;;
        4) udpcustom_menu ;;
        5) slowdns_menu ;;
        6) cloudflared_menu ;;
        7) webpanel_menu ;;
        8) status_page ;;
        9) tools_menu ;;
        10) sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; echo "RAM cleared"; pause ;;
        11) read -rp "Reboot the VPS now? [y/N] " a; [ "$a" = y ] && reboot ;;
        12) read -rp "UNINSTALL Ragnar Panel completely? [y/N] " a
            [ "$a" = y ] && bash "$RAGNAR_DIR/uninstall.sh" ;;
        x|X) clear; echo "Bye - @farisbazed / https://t.me/ragnaresim"; exit 0 ;;
    esac
done
