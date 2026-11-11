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
    # bandwidth (vnstat when available)
    local btoday bmonth
    if command -v vnstat >/dev/null; then
        # --oneline fields: 6 = today total, 11 = this month total.
        # Guard against vnstat's "No data" prose leaking into the header.
        btoday=$(vnstat --oneline 2>/dev/null | cut -d';' -f6 | grep -E '^[0-9]' || true)
        bmonth=$(vnstat --oneline 2>/dev/null | cut -d';' -f11 | grep -E '^[0-9]' || true)
        [ -n "$btoday" ] || btoday=""
        [ -n "$bmonth" ] || bmonth=""
    fi
    bar "BANDWIDTH"
    printf "${C}%-14s${W}: ${G}%-18s${C}%-14s${W}: ${G}%s${N}\n" \
        "TODAY" "${btoday:-n/a}" "MONTH" "${bmonth:-n/a}"
    # user stats
    local stats total online
    stats=$(python3 "$CORE" stats 2>/dev/null)
    get() { echo "$stats" | grep -o "\"$1\": [0-9]*" | grep -o '[0-9]*$'; }
    total=$(get total); online=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
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
    printf "${C}%-13s${W}: %-22s${C}%-13s${W}: %s${N}\n" "SLOWDNS" "$(svc_dot slowdns)" "CLOUDFLARED" "$(svc_dot_cf)"
}

main_menu() {
    bar "MAIN MENU"
    printf "${P}〈${Y}1${P}〉${W}  SSH & SSL        ${P}〈${Y}9${P}〉${W}  UDP CUSTOM\n"
    printf "${P}〈${Y}2${P}〉${W}  VMESS            ${P}〈${Y}10${P}〉${W} SLOWDNS\n"
    printf "${P}〈${Y}3${P}〉${W}  VLESS            ${P}〈${Y}11${P}〉${W} CLOUDFLARED\n"
    printf "${P}〈${Y}4${P}〉${W}  TROJAN           ${P}〈${Y}12${P}〉${W} TOOLS\n"
    printf "${P}〈${Y}5${P}〉${W}  SSWS             ${P}〈${Y}13${P}〉${W} STATUS\n"
    printf "${P}〈${Y}6${P}〉${W}  ANYTLS           ${P}〈${Y}14${P}〉${W} CLEAR RAM\n"
    printf "${P}〈${Y}7${P}〉${W}  XRAY (ALL)       ${P}〈${Y}15${P}〉${W} REBOOT VPS\n"
    printf "${P}〈${Y}8${P}〉${W}  UDP ZIVPN        ${P}〈${Y}16${P}〉${W} UNINSTALL\n"
    printf "${P}〈${Y}x${P}〉${W}  EXIT\n"
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
    echo "1) Renew/extend days   2) Set quota GB   3) Set IP limit"
    echo "4) Change password     5) Enable         6) Disable"
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
        echo "1) Create user    2) List users    3) Edit / renew user"
        echo "4) Delete user    5) User info (ports, SNI, payloads)    0) Back"
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
    local u proto; read -rp "Username: " u; proto="${1:-}"
    if [ -n "$proto" ]; then
        python3 "$CORE" xray-links "$u" | grep -i -A1 "$proto" || python3 "$CORE" xray-links "$u"
    else
        python3 "$CORE" xray-links "$u"
    fi
    pause
}
xray_edit() {
    local u what
    read -rp "Username to edit: " u
    echo "1) Renew/extend days   2) Set quota GB   3) Set IP limit   4) Enable   5) Disable"
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
    local focus="${1:-ALL}"
    while true; do
        print_header; bar "XRAY - $focus"
        echo "1) Create user (all protocols at once)   2) List users"
        echo "3) Edit / renew user                      4) Delete user"
        echo "5) Show links                             0) Back"
        read -rp "Choice: " c
        case $c in
            1) xray_create ;; 2) python3 "$CORE" xray-list; pause ;;
            3) xray_edit ;; 4) xray_del ;;
            5) [ "$focus" = ALL ] && xray_links || xray_links "$focus" ;;
            0) return ;;
        esac
    done
}

# ---------------------------------------------------------------------
# UDP ZIVPN / UDP Custom / SlowDNS / Cloudflared
# ---------------------------------------------------------------------
zivpn_menu() {
    while true; do
        print_header; bar "UDP ZIVPN (port 5667)"
        echo "1) Create user    2) List users    3) Delete user"
        echo "4) Server info    5) Restart       0) Back"
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
        echo "1) Restart    2) Status log    0) Back"
        read -rp "Choice: " c
        case $c in
            1) systemctl restart udp-custom udpgw; echo restarted; pause ;;
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
        echo "1) Restart    2) Set nameserver    0) Back"
        read -rp "Choice: " c
        case $c in
            1) systemctl restart slowdns; echo restarted; pause ;;
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
        echo "1) Set domain (for TLS + CF links)"
        echo "2) Set CF hostname used in links"
        echo "3) Install named-tunnel token & enable service"
        echo "4) Start a quick tunnel (trycloudflare, prints a temp hostname)"
        echo "0) Back"
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
# Tools / status
# ---------------------------------------------------------------------
tools_menu() {
    while true; do
        print_header; bar "TOOLS"
        echo "1) Restart ALL services      2) Backup users (tar.gz)"
        echo "3) Run limit checker now     4) Speed test (fast.com via curl)"
        echo "5) Listening ports           0) Back"
        read -rp "Choice: " c
        case $c in
            1) systemctl restart haproxy xray sing-box ragnar-wsproxy dropbear \
                   zivpn udp-custom udpgw slowdns 2>/dev/null; echo done; pause ;;
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
             udpgw slowdns cloudflared ragnar-watchdog.timer; do
        printf "${C}%-24s${W}: %s${N}\n" "$s" "$(svc_dot $s)"
    done
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
        2) xray_menu VMESS ;;
        3) xray_menu VLESS ;;
        4) xray_menu TROJAN ;;
        5) xray_menu SSWS ;;
        6) xray_menu ANYTLS ;;
        7) xray_menu ALL ;;
        8) zivpn_menu ;;
        9) udpcustom_menu ;;
        10) slowdns_menu ;;
        11) cloudflared_menu ;;
        12) tools_menu ;;
        13) status_page ;;
        14) sync; echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; echo "RAM cleared"; pause ;;
        15) read -rp "Reboot the VPS now? [y/N] " a; [ "$a" = y ] && reboot ;;
        16) read -rp "UNINSTALL Ragnar Panel completely? [y/N] " a
            [ "$a" = y ] && bash "$RAGNAR_DIR/uninstall.sh" ;;
        x|X) clear; echo "Bye - @farisbazed / https://t.me/ragnaresim"; exit 0 ;;
    esac
done
