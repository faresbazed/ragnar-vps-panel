#!/usr/bin/env python3
"""
Ragnar VPS Management Panel - core engine
=========================================
Single-file, stdlib-only core. Owns:
  * the user databases (SSH users + Xray users) as JSON under RAGNAR_DIR
  * Xray / sing-box config generation (all protocols generated together)
  * share-link generation (direct 80, direct TLS 443, Cloudflare 80, Cloudflare 443)
  * expiry / GB-quota / IP-limit enforcement checks (pure logic, unit-tested)

Environment:
  RAGNAR_DIR   state dir (default /etc/ragnar)
  RAGNAR_HOST  public host/IP used in links (or <RAGNAR_DIR>/host file)
  RAGNAR_DOMAIN  domain used for SNI / Cloudflare (or <RAGNAR_DIR>/domain file)
  RAGNAR_CF_HOST Cloudflare hostname for CF links (defaults to the domain)

No third-party packages. Python 3.8+.
"""
import base64
import datetime as _dt
import json
import os
import subprocess
import sys
import uuid as _uuid

VERSION = "1.0.0"
TG_USER = "@farisbazed"
TG_CHANNEL = "https://t.me/ragnaresim"

BASE = os.environ.get("RAGNAR_DIR", "/etc/ragnar")
DB_DIR = os.path.join(BASE, "db")
SSH_DB = os.path.join(DB_DIR, "ssh.json")
XRAY_DB = os.path.join(DB_DIR, "xray.json")
ZIVPN_DB = os.path.join(DB_DIR, "zivpn.json")
SETTINGS = os.path.join(BASE, "settings.json")

# WebSocket paths - one per protocol, all behind the HAProxy front door.
PATHS = {
    "vless": "/ragnar-vless",
    "vmess": "/ragnar-vmess",
    "trojan": "/ragnar-trojan",
    "ssws": "/ragnar-ssws",
    "sshws": "/ragnar-sshws",
}
# Loopback backend ports (never exposed directly; HAProxy owns 80/443)
BACKEND = {
    "vless": 10001,
    "vmess": 10002,
    "trojan": 10003,
    "ssws": 10004,
    "sshws": 10005,      # python wsproxy -> dropbear/openssh
    "anytls": 10006,     # sing-box (raw TLS, reached by SNI passthrough)
}
SS_METHOD = "2022-blake3-aes-128-gcm"


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def _now():
    return _dt.datetime.now(_dt.timezone.utc)


def _today():
    return _now().date()


def _read_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def _write_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
    os.replace(tmp, path)


def load_settings():
    s = _read_json(SETTINGS, {})
    def _file(name):
        try:
            with open(os.path.join(BASE, name), encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return ""
    return {
        "host": os.environ.get("RAGNAR_HOST") or s.get("host") or _file("host"),
        "domain": os.environ.get("RAGNAR_DOMAIN") or s.get("domain") or _file("domain"),
        "cf_host": os.environ.get("RAGNAR_CF_HOST") or s.get("cf_host") or "",
        "ns": s.get("ns", ""),                    # SlowDNS nameserver, e.g. ns.example.com
        "slowdns_pubkey": s.get("slowdns_pubkey", ""),
    }


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode().strip()


def b64url_nopad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def expiry_from_days(days: int) -> str:
    return (_today() + _dt.timedelta(days=int(days))).isoformat()


def days_left(expiry: str) -> int:
    try:
        return (_dt.date.fromisoformat(expiry) - _today()).days
    except ValueError:
        return -9999


def is_expired(expiry: str) -> bool:
    return days_left(expiry) < 0


# --------------------------------------------------------------------------
# SSH users
# --------------------------------------------------------------------------
def load_ssh():
    return _read_json(SSH_DB, {"users": {}})["users"]


def save_ssh(users):
    _write_json(SSH_DB, {"users": users})


def ssh_add(username, password, days, quota_gb, ip_limit):
    users = load_ssh()
    if username in users:
        raise ValueError(f"SSH user '{username}' already exists")
    users[username] = {
        "password": password,
        "created": _today().isoformat(),
        "expiry": expiry_from_days(days),
        "quota_gb": float(quota_gb),
        "used_bytes": 0,
        "ip_limit": int(ip_limit),
        "enabled": True,
    }
    save_ssh(users)
    return users[username]


def ssh_edit(username, days=None, quota_gb=None, ip_limit=None, password=None,
             extend=False, enable=None):
    users = load_ssh()
    if username not in users:
        raise ValueError(f"SSH user '{username}' not found")
    u = users[username]
    if days is not None:
        if extend:
            base = max(_dt.date.fromisoformat(u["expiry"]), _today())
            u["expiry"] = (base + _dt.timedelta(days=int(days))).isoformat()
        else:
            u["expiry"] = expiry_from_days(days)
    if quota_gb is not None:
        u["quota_gb"] = float(quota_gb)
    if ip_limit is not None:
        u["ip_limit"] = int(ip_limit)
    if password:
        u["password"] = password
    if enable is not None:
        u["enabled"] = bool(enable)
    save_ssh(users)
    return u


def ssh_del(username):
    users = load_ssh()
    if username not in users:
        raise ValueError(f"SSH user '{username}' not found")
    del users[username]
    save_ssh(users)


# --------------------------------------------------------------------------
# Xray users - one identity generates every protocol at the same time
# --------------------------------------------------------------------------
def load_xray():
    return _read_json(XRAY_DB, {"users": {}})["users"]


def save_xray(users):
    _write_json(XRAY_DB, {"users": users})


def _ss_password():
    # 2022-blake3-aes-128-gcm keys are standard base64 of exactly 16 bytes
    return base64.b64encode(os.urandom(16)).decode()


def _ss_server_key():
    raw = _read_json(SETTINGS, {})
    key = raw.get("ss_server_key")
    if not key:
        key = base64.b64encode(os.urandom(16)).decode()
        raw["ss_server_key"] = key
        _write_json(SETTINGS, raw)
    return key


def xray_add(name, days, quota_gb=0, ip_limit=0):
    users = load_xray()
    if name in users:
        raise ValueError(f"Xray user '{name}' already exists")
    users[name] = {
        "uuid": str(_uuid.uuid4()),
        "password": _ss_password(),          # trojan / anytls password
        "ss_password": _ss_password(),       # shadowsocks-2022 password
        "created": _today().isoformat(),
        "expiry": expiry_from_days(days),
        "quota_gb": float(quota_gb),
        "used_bytes": 0,
        "ip_limit": int(ip_limit),
        "enabled": True,
    }
    save_xray(users)
    return users[name]


def xray_edit(name, days=None, quota_gb=None, ip_limit=None, extend=False, enable=None):
    users = load_xray()
    if name not in users:
        raise ValueError(f"Xray user '{name}' not found")
    u = users[name]
    if days is not None:
        if extend:
            base = max(_dt.date.fromisoformat(u["expiry"]), _today())
            u["expiry"] = (base + _dt.timedelta(days=int(days))).isoformat()
        else:
            u["expiry"] = expiry_from_days(days)
    if quota_gb is not None:
        u["quota_gb"] = float(quota_gb)
    if ip_limit is not None:
        u["ip_limit"] = int(ip_limit)
    if enable is not None:
        u["enabled"] = bool(enable)
    save_xray(users)
    return u


def xray_del(name):
    users = load_xray()
    if name not in users:
        raise ValueError(f"Xray user '{name}' not found")
    del users[name]
    save_xray(users)


def active_xray_users():
    return {n: u for n, u in load_xray().items()
            if u.get("enabled", True) and not is_expired(u["expiry"])}


# --------------------------------------------------------------------------
# ZIVPN passwords (auth is by password list; account = SSH-style record)
# --------------------------------------------------------------------------
def load_zivpn():
    return _read_json(ZIVPN_DB, {"users": {}})["users"]


def zivpn_add(name, password, days):
    users = load_zivpn()
    if name in users:
        raise ValueError(f"ZIVPN user '{name}' already exists")
    users[name] = {"password": password, "created": _today().isoformat(),
                   "expiry": expiry_from_days(days), "enabled": True}
    _write_json(ZIVPN_DB, {"users": users})
    return users[name]


def zivpn_del(name):
    users = load_zivpn()
    if name not in users:
        raise ValueError(f"ZIVPN user '{name}' not found")
    del users[name]
    _write_json(ZIVPN_DB, {"users": users})


def zivpn_passwords():
    return [u["password"] for u in load_zivpn().values()
            if u.get("enabled", True) and not is_expired(u["expiry"])]


# --------------------------------------------------------------------------
# Config generation
# --------------------------------------------------------------------------
def gen_xray_config():
    users = active_xray_users()

    def ws_settings(path):
        return {"network": "ws",
                "wsSettings": {"path": path, "headers": {"Host": ""}},
                "security": "none"}

    def clients(proto):
        out = []
        for name, u in sorted(users.items()):
            if proto in ("vless", "vmess"):
                out.append({"id": u["uuid"], "email": name})
            elif proto == "trojan":
                out.append({"password": u["password"], "email": name})
            elif proto == "ssws":
                out.append({"password": u["ss_password"], "email": name})
        return out

    def inbound(tag, proto, port, extra=None):
        settings = {"clients": clients(proto)} if proto != "ssws" else {
            "method": SS_METHOD, "password": _ss_server_key(),
            "network": "tcp,udp", "clients": clients("ssws")}
        if proto == "trojan":
            settings["fallbacks"] = []
        if proto == "vless":
            settings["decryption"] = "none"
        cfg = {"tag": tag, "listen": "127.0.0.1", "port": port,
               "protocol": {"ssws": "shadowsocks"}.get(proto, proto),
               "settings": settings,
               "streamSettings": ws_settings(PATHS[proto]),
               "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}}
        if extra:
            cfg.update(extra)
        return cfg

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "api", "listen": "127.0.0.1", "port": 10085,
             "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}},
            inbound("vless-ws", "vless", BACKEND["vless"]),
            inbound("vmess-ws", "vmess", BACKEND["vmess"]),
            inbound("trojan-ws", "trojan", BACKEND["trojan"]),
            inbound("ss-ws", "ssws", BACKEND["ssws"]),
        ],
        "outbounds": [
            {"protocol": "freedom", "tag": "direct",
             "settings": {"domainStrategy": "UseIPv4"}},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"}]},
        # per-user traffic counters, read by the panel for GB quotas
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
                   "system": {"statsInboundUplink": True, "statsInboundDownlink": True}},
    }
    return config


def gen_singbox_config():
    """AnyTLS lives in sing-box: Xray-core has no AnyTLS implementation."""
    users = active_xray_users()
    s = load_settings()
    cert = os.path.join(BASE, "certs", "fullchain.pem")
    key = os.path.join(BASE, "certs", "privkey.pem")
    return {
        "log": {"level": "warn"},
        "inbounds": [{
            "type": "anytls", "tag": "anytls-in",
            "listen": "::", "listen_port": BACKEND["anytls"],
            "users": [{"name": n, "password": u["password"]}
                      for n, u in sorted(users.items())],
            "padding_scheme": [
                "stop=8",
                "0=30-30", "1=100-400", "2=400-500,c,500-1000,c,500-1000,c,500-1000",
                "3=9-9,500-1000", "4=500-1000", "5=500-1000", "6=500-1000",
                "7=500-1000",
            ],
            "tls": {"enabled": True,
                    "server_name": s["domain"] or s["host"],
                    "certificate_path": cert, "key_path": key},
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }


def gen_zivpn_config():
    return {
        "listen": ":5667",
        "cert": os.path.join(BASE, "certs", "zivpn.crt"),
        "key": os.path.join(BASE, "certs", "zivpn.key"),
        "obfs": "zivpn",
        "auth": {"mode": "passwords", "config": zivpn_passwords() or ["ragnar-default-change-me"]},
    }


# --------------------------------------------------------------------------
# Share links
# --------------------------------------------------------------------------
def _variants():
    """(label, address, port, security) for the four WS routes."""
    s = load_settings()
    host = s["domain"] or s["host"]
    cf = s["cf_host"] or s["domain"] or s["host"]
    return [
        ("WS  · port 80 (direct)", host, 80, "none"),
        ("WSS · port 443 (direct)", host, 443, "tls"),
        ("WS  · port 80 (Cloudflare)", cf, 80, "none"),
        ("WSS · port 443 (Cloudflare)", cf, 443, "tls"),
    ]


def _ws_params(addr, port, security, path, extra_host=""):
    q = f"type=ws&path={path}&host={extra_host or addr}"
    if security == "tls":
        q += f"&security=tls&sni={addr}&fp=chrome&alpn=http%2F1.1"
    else:
        q += "&security=none"
    return q


def links_for(name):
    users = load_xray()
    if name not in users:
        raise ValueError(f"Xray user '{name}' not found")
    u = users[name]
    s = load_settings()
    out = {}
    for label, addr, port, sec in _variants():
        tag = f"Ragnar-{name}"
        vless = (f"vless://{u['uuid']}@{addr}:{port}?"
                 f"encryption=none&{_ws_params(addr, port, sec, PATHS['vless'])}#{tag}-VLESS")
        vmess_obj = {"v": "2", "ps": f"{tag}-VMESS", "add": addr, "port": str(port),
                     "id": u["uuid"], "aid": "0", "scy": "auto", "net": "ws",
                     "type": "none", "host": addr, "path": PATHS["vmess"],
                     "tls": "tls" if sec == "tls" else "", "sni": addr if sec == "tls" else "",
                     "alpn": "http/1.1" if sec == "tls" else "", "fp": "chrome"}
        vmess = "vmess://" + b64e(json.dumps(vmess_obj, separators=(",", ":")).encode())
        trojan = (f"trojan://{u['password']}@{addr}:{port}?"
                  f"{_ws_params(addr, port, sec, PATHS['trojan'])}#{tag}-TROJAN")
        ss_plain = b64url_nopad(f"{SS_METHOD}:{u['ss_password']}".encode())
        ssws = f"ss://{ss_plain}@{addr}:{port}?type=ws&path={PATHS['ssws']}&host={addr}"
        if sec == "tls":
            ssws += f"&security=tls&sni={addr}"
        ssws += f"#{tag}-SSWS"
        out[label] = {"VLESS": vless, "VMESS": vmess, "TROJAN": trojan, "SSWS": ssws}
    # AnyTLS: raw TLS, cannot ride Cloudflare's HTTP proxy - direct only.
    # The 443 link MUST carry SNI anytls.<domain>: HAProxy's stage-1 SNI
    # router is what steers it (passthrough) to sing-box instead of the
    # TLS-termination stage. Needs an A record for anytls.<domain>.
    host = s["domain"] or s["host"]
    anytls_sni = f"anytls.{s['domain']}" if s["domain"] else host
    out["AnyTLS · port 443 (direct, SNI routed)"] = {
        "ANYTLS": (f"anytls://{u['password']}@{host}:443?"
                   f"security=tls&sni={anytls_sni}&fp=chrome&alpn=h2#Ragnar-{name}-ANYTLS"),
    }
    sni_host = anytls_sni
    out["AnyTLS · port 8446 (direct fallback)"] = {
        "ANYTLS": (f"anytls://{u['password']}@{host}:8446?"
                   f"security=tls&sni={sni_host}&fp=chrome&alpn=h2#Ragnar-{name}-ANYTLS-8446"),
    }
    return out


def ssh_info(username):
    users = load_ssh()
    if username not in users:
        raise ValueError(f"SSH user '{username}' not found")
    u = users[username]
    s = load_settings()
    host = s["domain"] or s["host"]
    return {
        "username": username, "password": u["password"], "host": host,
        "ssh_port": 22, "dropbear_port": 109,
        "ws_port": 80, "wss_port": 443, "ssl_port": 443,
        "ws_path": PATHS["sshws"], "ws_path_framed": "/ragnar-sshwsf",
        "sni": host,
        "slowdns_ns": s["ns"], "slowdns_pubkey": s["slowdns_pubkey"],
        "udp_zivpn_port": 5667, "udp_custom_port": "1-65535",
        "expiry": u["expiry"], "days_left": days_left(u["expiry"]),
        "quota_gb": u["quota_gb"], "ip_limit": u["ip_limit"],
    }


# --------------------------------------------------------------------------
# Enforcement logic (pure - unit tested; the cron wrapper acts on results)
# --------------------------------------------------------------------------
def quota_exceeded(used_bytes, quota_gb):
    if not quota_gb or float(quota_gb) <= 0:
        return False
    return int(used_bytes) >= int(float(quota_gb) * 1024 ** 3)


def ip_limit_exceeded(distinct_ips, ip_limit):
    if not ip_limit or int(ip_limit) <= 0:
        return False
    return len(set(distinct_ips)) > int(ip_limit)


def enforcement_plan(ssh_users, xray_users, live_ips):
    """Return {action-list} for expired / over-quota / over-IP users."""
    plan = []
    for name, u in ssh_users.items():
        if is_expired(u["expiry"]):
            plan.append({"kind": "ssh", "user": name, "action": "lock", "reason": "expired"})
        elif quota_exceeded(u.get("used_bytes", 0), u.get("quota_gb", 0)):
            plan.append({"kind": "ssh", "user": name, "action": "lock", "reason": "quota"})
        elif ip_limit_exceeded(live_ips.get(("ssh", name), []), u.get("ip_limit", 0)):
            plan.append({"kind": "ssh", "user": name, "action": "kick-extra",
                         "reason": "ip-limit"})
    for name, u in xray_users.items():
        if is_expired(u["expiry"]):
            plan.append({"kind": "xray", "user": name, "action": "remove", "reason": "expired"})
        elif quota_exceeded(u.get("used_bytes", 0), u.get("quota_gb", 0)):
            plan.append({"kind": "xray", "user": name, "action": "remove", "reason": "quota"})
    return plan


def stats():
    ssh = load_ssh()
    xray = load_xray()
    ziv = load_zivpn()
    return {
        "ssh": len(ssh), "vless": len(xray), "vmess": len(xray),
        "trojan": len(xray), "ssws": len(xray), "anytls": len(xray),
        "zivpn": len(ziv),
        "total": len(ssh) + len(xray) + len(ziv),
    }


# --------------------------------------------------------------------------
# System side effects (only used by the on-VPS wrapper commands)
# --------------------------------------------------------------------------
def _run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def apply_configs():
    _write_json(os.path.join(BASE, "xray", "config.json"), gen_xray_config())
    _write_json(os.path.join(BASE, "sing-box", "config.json"), gen_singbox_config())
    _write_json(os.path.join(BASE, "zivpn", "config.json"), gen_zivpn_config())
    _run("systemctl restart xray 2>/dev/null; systemctl restart sing-box 2>/dev/null; "
         "systemctl restart zivpn 2>/dev/null; true")


def sync_linux_user(username, password, expiry, enabled=True):
    """Create/update the real Linux account behind an SSH DB record."""
    exists = _run(f"id {username} >/dev/null 2>&1").returncode == 0
    if not exists:
        _run(f"useradd -m -s /bin/false -e {expiry} {username}")
    _run(f"echo '{username}:{password}' | chpasswd")
    _run(f"chage -E {expiry} {username}")
    _run(f"usermod {'-U' if enabled else '-L'} {username}")


# --------------------------------------------------------------------------
# Human-readable display (the menu prints these verbatim; pass --json to
# the list/info/links commands to get the old machine format instead)
# --------------------------------------------------------------------------
def _qstr(quota_gb):
    return "unlimited" if not quota_gb else f"{float(quota_gb):g} GB"


def _istr(ip_limit):
    return "unlimited" if not ip_limit else str(ip_limit)


def fmt_links(name):
    lines = [f"Xray user: {name}"]
    for label, protos in links_for(name).items():
        lines.append("")
        lines.append(f"-- {label} --")
        for proto, link in protos.items():
            lines.append(f"{proto:<7} {link}")
    return "\n".join(lines)


def fmt_users(users):
    if not users:
        return "No users yet."
    lines = [f"{'NAME':<16}{'EXPIRES':<12}{'LEFT':<7}{'QUOTA':<11}{'IP LIMIT':<10}STATUS"]
    for n, u in users.items():
        lines.append(
            f"{n:<16}{u['expiry']:<12}{str(u['days_left']) + 'd':<7}"
            f"{_qstr(u['quota_gb']):<11}{_istr(u['ip_limit']):<10}"
            f"{'active' if u.get('enabled', True) else 'DISABLED'}")
    return "\n".join(lines)


def fmt_zivpn_users(users):
    if not users:
        return "No users yet."
    lines = [f"{'NAME':<16}{'EXPIRES':<12}LEFT"]
    for n, u in users.items():
        lines.append(f"{n:<16}{u['expiry']:<12}{u['days_left']}d")
    return "\n".join(lines)


def fmt_ssh_info(username):
    i = ssh_info(username)
    return "\n".join([
        f"SSH user : {i['username']}",
        f"Password : {i['password']}",
        f"Host     : {i['host']}",
        f"Direct   : SSH port {i['ssh_port']} - Dropbear port {i['dropbear_port']}",
        f"SSH-WS   : port {i['ws_port']}, path {i['ws_path']} (framed: {i['ws_path_framed']})",
        f"SSH-WSS  : port {i['wss_port']} (also SSH-SSL, SNI {i['sni']})",
        f"SlowDNS  : NS {i['slowdns_ns']}",
        f"           pubkey {i['slowdns_pubkey']}",
        f"UDP      : ZIVPN port {i['udp_zivpn_port']} - UDP Custom ports {i['udp_custom_port']}",
        f"Expires  : {i['expiry']} ({i['days_left']} days left)",
        f"Quota    : {_qstr(i['quota_gb'])} - IP limit: {_istr(i['ip_limit'])}",
    ])


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def _p(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def main(argv):
    if not argv:
        print(__doc__)
        return 1
    cmd, args = argv[0], argv[1:]
    try:
        if cmd == "ssh-add":
            u, p, d, q, i = args[0], args[1], int(args[2]), float(args[3]), int(args[4])
            rec = ssh_add(u, p, d, q, i)
            sync_linux_user(u, p, rec["expiry"])
            print(f"SSH user '{u}' created.\n\n{fmt_ssh_info(u)}")
        elif cmd == "ssh-edit":
            kw = {}
            i = 1
            while i < len(args):
                k = args[i].lstrip("-").replace("-", "_")
                if k in ("days", "quota_gb", "ip_limit"):
                    kw[k] = float(args[i + 1]) if k == "quota_gb" else int(args[i + 1]); i += 2
                elif k == "password":
                    kw[k] = args[i + 1]; i += 2
                elif k == "extend":
                    kw["extend"] = True; i += 1
                elif k == "enable":
                    kw["enable"] = True; i += 1
                elif k == "disable":
                    kw["enable"] = False; i += 1
                else:
                    i += 1
            u = ssh_edit(args[0], **kw)
            sync_linux_user(args[0], u["password"], u["expiry"], u.get("enabled", True))
            print(f"SSH user '{args[0]}' saved.\n\n{fmt_ssh_info(args[0])}")
        elif cmd == "ssh-del":
            ssh_del(args[0]); _run(f"userdel -r {args[0]} 2>/dev/null; true")
            print(f"SSH user '{args[0]}' deleted.")
        elif cmd == "ssh-list":
            data = {n: {"expiry": u["expiry"], "days_left": days_left(u["expiry"]),
                        "quota_gb": u["quota_gb"], "ip_limit": u["ip_limit"],
                        "enabled": u.get("enabled", True)}
                    for n, u in load_ssh().items()}
            _p(data) if "--json" in args else print(fmt_users(data))
        elif cmd == "ssh-info":
            _p(ssh_info(args[0])) if "--json" in args[1:] else print(fmt_ssh_info(args[0]))
        elif cmd == "xray-add":
            name = args[0]; d = int(args[1])
            q = float(args[2]) if len(args) > 2 else 0
            i = int(args[3]) if len(args) > 3 else 0
            xray_add(name, d, q, i); apply_configs()
            print(f"Xray user '{name}' created.\n\n{fmt_links(name)}")
        elif cmd == "xray-edit":
            kw = {}
            i = 1
            while i < len(args):
                k = args[i].lstrip("-").replace("-", "_")
                if k in ("days", "quota_gb", "ip_limit"):
                    kw[k] = float(args[i + 1]) if k == "quota_gb" else int(args[i + 1]); i += 2
                elif k == "extend":
                    kw["extend"] = True; i += 1
                elif k == "enable":
                    kw["enable"] = True; i += 1
                elif k == "disable":
                    kw["enable"] = False; i += 1
                else:
                    i += 1
            xray_edit(args[0], **kw); apply_configs()
            print(f"Xray user '{args[0]}' saved.\n\n{fmt_links(args[0])}")
        elif cmd == "xray-del":
            xray_del(args[0]); apply_configs()
            print(f"Xray user '{args[0]}' deleted.")
        elif cmd == "xray-list":
            data = {n: {"expiry": u["expiry"], "days_left": days_left(u["expiry"]),
                        "quota_gb": u["quota_gb"], "ip_limit": u["ip_limit"],
                        "enabled": u.get("enabled", True)}
                    for n, u in load_xray().items()}
            _p(data) if "--json" in args else print(fmt_users(data))
        elif cmd == "xray-links":
            _p(links_for(args[0])) if "--json" in args[1:] else print(fmt_links(args[0]))
        elif cmd == "zivpn-add":
            zivpn_add(args[0], args[1], int(args[2])); apply_configs()
            print(f"ZIVPN user '{args[0]}' created.")
        elif cmd == "zivpn-del":
            zivpn_del(args[0]); apply_configs()
            print(f"ZIVPN user '{args[0]}' deleted.")
        elif cmd == "zivpn-list":
            data = {n: {"expiry": u["expiry"], "days_left": days_left(u["expiry"])}
                    for n, u in load_zivpn().items()}
            _p(data) if "--json" in args else print(fmt_zivpn_users(data))
        elif cmd == "gen-configs":
            apply_configs(); _p({"ok": True})
        elif cmd == "stats":
            _p(stats())
        elif cmd == "version":
            print(VERSION)
        else:
            print(f"unknown command: {cmd}", file=sys.stderr)
            return 2
    except (ValueError, IndexError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
