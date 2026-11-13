#!/usr/bin/env python3
"""
Ragnar Web Panel - a 3x-ui style web UI for the Ragnar VPS panel.

Single file, Python standard library only. Two serving modes:
  * fronted (what install.sh sets up): plain HTTP on 127.0.0.1:2053
    under the /panel prefix, reached as https://<domain>/panel through
    HAProxy on 443 - providers like IONOS firewall inbound 2053 before
    it ever reaches the box, but 443 is always open.
  * direct: HTTPS on port 2053 (3x-ui's port) with the panel's own
    domain certificate (<RAGNAR_DIR>/certs/fullchain.pem + privkey.pem).
Env switches: RAGNAR_WEB_BASE, RAGNAR_WEB_BIND, RAGNAR_WEB_NO_TLS,
RAGNAR_WEB_PORT.

All user management goes through core/ragnar.py - the same functions
the terminal menu uses - so the two UIs can never drift apart.

Login credentials live in <RAGNAR_DIR>/web.json (PBKDF2-HMAC-SHA256,
never plaintext). Manage them with:
    python3 webpanel.py --init             # create admin + random password
    python3 webpanel.py --reset-password   # new random password, printed once
    python3 webpanel.py --set-password USER PASS
"""
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import shutil
import ssl
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "core"))
import ragnar  # noqa: E402

BASE = ragnar.BASE
WEB_JSON = os.path.join(BASE, "web.json")
DEFAULT_PORT = 2053
# When fronted by HAProxy the app lives under a path prefix on the main
# HTTPS port (2053 direct is blocked by some providers' firewalls):
#   RAGNAR_WEB_BASE=/panel  RAGNAR_WEB_BIND=127.0.0.1  RAGNAR_WEB_NO_TLS=1
BASE_PATH = os.environ.get("RAGNAR_WEB_BASE", "").rstrip("/")


def U(path):
    """Public URL for an app path, honouring the HAProxy prefix."""
    return BASE_PATH + path
SESSION_TTL = 12 * 3600
SERVICES = ["haproxy", "xray", "sing-box", "ragnar-wsproxy", "dropbear",
            "ssh", "zivpn", "udp-custom", "badvpn-udpgw", "slowdns",
            "cloudflared", "ragnar-web"]
_failures = {}  # ip -> (count, locked_until)


# ---------------------------------------------------------------------
# Credentials / sessions
# ---------------------------------------------------------------------
def _hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex(), dk.hex()


def load_web_cfg():
    cfg = ragnar._read_json(WEB_JSON, {})
    cfg.setdefault("username", "admin")
    cfg.setdefault("port", DEFAULT_PORT)
    if "secret" not in cfg:
        cfg["secret"] = secrets.token_hex(32)
    return cfg


def save_web_cfg(cfg):
    os.makedirs(BASE, exist_ok=True)
    tmp = WEB_JSON + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(cfg, fh, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, WEB_JSON)


def set_password(username, password):
    cfg = load_web_cfg()
    salt, dk = _hash_password(password)
    cfg.update({"username": username, "salt": salt, "hash": dk})
    save_web_cfg(cfg)
    return cfg


def check_password(username, password):
    cfg = load_web_cfg()
    if username != cfg.get("username") or "hash" not in cfg:
        return False
    _, dk = _hash_password(password, bytes.fromhex(cfg["salt"]))
    return hmac.compare_digest(dk, cfg["hash"])


def make_session(username):
    cfg = load_web_cfg()
    payload = base64.urlsafe_b64encode(json.dumps(
        {"u": username, "exp": int(time.time()) + SESSION_TTL}
    ).encode()).decode()
    sig = hmac.new(cfg["secret"].encode(), payload.encode(),
                   hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def check_session(token):
    try:
        cfg = load_web_cfg()
        payload, sig = token.rsplit(".", 1)
        good = hmac.new(cfg["secret"].encode(), payload.encode(),
                        hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, good):
            return None
        data = json.loads(base64.urlsafe_b64decode(payload.encode()))
        if data.get("exp", 0) < time.time() or data.get("u") != cfg["username"]:
            return None
        return data["u"]
    except Exception:
        return None


def csrf_token(session_token):
    cfg = load_web_cfg()
    return hmac.new(cfg["secret"].encode(),
                    ("csrf:" + session_token).encode(),
                    hashlib.sha256).hexdigest()[:32]


def login_locked(ip):
    count, until = _failures.get(ip, (0, 0))
    return time.time() < until


def note_login_failure(ip):
    count, until = _failures.get(ip, (0, 0))
    count += 1
    if count >= 8:
        _failures[ip] = (0, time.time() + 300)
    else:
        _failures[ip] = (count, 0)


# ---------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------
def esc(x):
    return html.escape(str(x), quote=True)


def fmt_used(u):
    return ragnar.fmt_gb(int(u.get("used_bytes", 0)))


def fmt_quota(u):
    q = u.get("quota_gb") or 0
    return "Unlimited" if not q else ragnar.fmt_gb(int(q * 1024 ** 3))


def svc_active(unit):
    return subprocess.run(["systemctl", "is-active", "--quiet", unit],
                          capture_output=True).returncode == 0


def server_info():
    info = {}
    try:
        with open(os.path.join(BASE, "host")) as fh:
            info["ip"] = fh.read().strip()
    except OSError:
        info["ip"] = "-"
    info["os"] = ""
    try:
        with open("/etc/os-release") as fh:
            for line in fh:
                if line.startswith("PRETTY_NAME="):
                    info["os"] = line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    try:
        with open("/proc/uptime") as fh:
            secs = int(float(fh.read().split()[0]))
        info["uptime"] = f"{secs // 86400}d {(secs % 86400) // 3600}h"
    except OSError:
        info["uptime"] = "-"
    try:
        total = avail = 0
        with open("/proc/meminfo") as fh:
            for line in fh:
                if line.startswith("MemTotal:"):
                    total = int(line.split()[1])
                if line.startswith("MemAvailable:"):
                    avail = int(line.split()[1])
        info["ram"] = f"{(total - avail) // 1024}MB / {total // 1024}MB"
    except OSError:
        info["ram"] = "-"
    try:
        d = shutil.disk_usage("/")
        info["disk"] = f"{d.used / 2**30:.1f}G / {d.total / 2**30:.1f}G"
    except OSError:
        info["disk"] = "-"
    return info


# ---------------------------------------------------------------------
# HTML (3x-ui style: dark sidebar, cards, clean tables)
# ---------------------------------------------------------------------
CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: 'Segoe UI', system-ui, sans-serif; background: #0f172a;
       color: #e2e8f0; display: flex; min-height: 100vh; }
.sidebar { width: 230px; background: #111c33; padding: 22px 0; flex-shrink: 0;
           border-right: 1px solid #1e293b; }
.logo { padding: 0 22px 18px; font-size: 20px; font-weight: 700; color: #a78bfa; }
.logo small { display: block; font-size: 11px; color: #64748b; font-weight: 400; }
.nav a { display: block; padding: 11px 22px; color: #94a3b8; text-decoration: none;
         font-size: 14px; border-left: 3px solid transparent; }
.nav a:hover { color: #e2e8f0; background: #1e293b; }
.nav a.on { color: #fff; background: #1e293b; border-left-color: #8b5cf6; }
.main { flex: 1; padding: 26px 30px; max-width: 1180px; }
h1 { font-size: 21px; margin-bottom: 18px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
         gap: 14px; margin-bottom: 20px; }
.card { background: #1e293b; border: 1px solid #334155; border-radius: 10px;
        padding: 16px 18px; }
.card .k { font-size: 12px; color: #94a3b8; text-transform: uppercase;
           letter-spacing: .05em; }
.card .v { font-size: 19px; font-weight: 600; margin-top: 5px; }
.card .s { font-size: 12px; color: #64748b; margin-top: 3px; }
table { width: 100%; border-collapse: collapse; background: #1e293b;
        border: 1px solid #334155; border-radius: 10px; overflow: hidden; }
th, td { padding: 10px 13px; text-align: left; font-size: 13.5px;
         border-bottom: 1px solid #273549; }
th { background: #16223c; color: #94a3b8; font-size: 12px;
     text-transform: uppercase; letter-spacing: .04em; }
tr:last-child td { border-bottom: none; }
.dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
       margin-right: 6px; }
.on-dot { background: #22c55e; } .off-dot { background: #ef4444; }
.pill { padding: 2px 9px; border-radius: 20px; font-size: 11.5px; }
.pill.g { background: #14532d; color: #86efac; } .pill.r { background: #450a0a; color: #fca5a5; }
.pill.b { background: #1e3a8a; color: #93c5fd; }
.btn { background: #7c3aed; color: #fff; border: none; padding: 7px 14px;
       border-radius: 7px; cursor: pointer; font-size: 13px; text-decoration: none;
       display: inline-block; }
.btn:hover { background: #8b5cf6; }
.btn.sm { padding: 4px 10px; font-size: 12px; }
.btn.grey { background: #334155; } .btn.red { background: #b91c1c; }
form.inline { display: inline; }
input, select { background: #0f172a; border: 1px solid #334155; color: #e2e8f0;
       padding: 8px 10px; border-radius: 7px; font-size: 13.5px; }
.addform { background: #1e293b; border: 1px solid #334155; border-radius: 10px;
       padding: 16px; margin-bottom: 18px; display: flex; gap: 10px; flex-wrap: wrap;
       align-items: end; }
.addform label { font-size: 12px; color: #94a3b8; display: block; margin-bottom: 4px; }
.msg { background: #14532d; color: #bbf7d0; padding: 10px 14px; border-radius: 8px;
       margin-bottom: 16px; font-size: 13.5px; }
.err { background: #450a0a; color: #fecaca; }
.link-box { background: #0f172a; border: 1px solid #334155; border-radius: 8px;
       padding: 10px 12px; margin: 6px 0 14px; word-break: break-all;
       font-family: monospace; font-size: 12px; }
h3 { margin: 20px 0 8px; font-size: 15px; color: #c4b5fd; }
.login-wrap { margin: auto; width: 360px; max-width: 92vw; }
.login-card { background: #1e293b; border: 1px solid #334155; border-radius: 14px;
       padding: 34px 30px; }
.login-card h1 { text-align: center; color: #a78bfa; margin-bottom: 4px; }
.login-card p { text-align: center; color: #64748b; font-size: 13px; margin-bottom: 22px; }
.login-card label { font-size: 12.5px; color: #94a3b8; display: block; margin: 13px 0 5px; }
.login-card input { width: 100%; padding: 11px; }
.login-card .btn { width: 100%; padding: 11px; margin-top: 20px; font-size: 14.5px; }
.tblwrap { overflow-x: auto; -webkit-overflow-scrolling: touch;
       border-radius: 10px; }
.tblwrap table { min-width: 580px; }
.tblwrap td { white-space: nowrap; }
.editform { max-width: 520px; }
.editform label { font-size: 12.5px; color: #94a3b8; display: block;
       margin: 14px 0 5px; }
.editform input, .editform select { width: 100%; padding: 10px; }
@media (max-width: 880px) {
  body { flex-direction: column; }
  .sidebar { width: 100%; padding: 12px 0 0; border-right: none;
       border-bottom: 1px solid #1e293b; }
  .logo { padding: 0 16px 10px; font-size: 19px; }
  .logo small { display: inline-block; margin-left: 10px; }
  .logo small br { display: none; }
  .nav { display: flex; overflow-x: auto; padding: 0 6px 10px;
       -webkit-overflow-scrolling: touch; }
  .nav a { border-left: none; border-bottom: 3px solid transparent;
       padding: 8px 11px; white-space: nowrap; }
  .nav a.on { border-bottom-color: #8b5cf6; }
  .main { padding: 16px 12px; width: 100%; }
  .addform { flex-direction: column; align-items: stretch; }
  .addform input { width: 100%; }
  h1 { font-size: 19px; margin-bottom: 14px; }
}
"""


def layout(title, active, body, flash=""):
    nav = [(U("/"), "dashboard", "Dashboard"), (U("/ssh"), "ssh", "SSH & SSL"),
           (U("/xray"), "xray", "Xray"), (U("/zivpn"), "zivpn", "ZIVPN"),
           (U("/services"), "services", "Services"),
           (U("/settings"), "settings", "Settings"),
           (U("/logout"), "", "Logout")]
    links = "".join(
        f'<a href="{href}" class="{"on" if key == active else ""}">'
        f'<span>{label}</span></a>' for href, key, label in nav)
    msg = f'<div class="msg">{esc(flash)}</div>' if flash else ""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)} - Ragnar Panel</title><style>{CSS}</style></head>
<body><div class="sidebar"><div class="logo">RAGNAR<small>
VPS Management Panel<br>by @farisbazed</small></div>
<div class="nav">{links}</div></div>
<div class="main"><h1>{esc(title)}</h1>{msg}{body}</div></body></html>"""


def login_page(error=""):
    err = f'<div class="msg err">{esc(error)}</div>' if error else ""
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login - Ragnar Panel</title><style>{CSS}</style></head>
<body><div class="login-wrap"><div class="login-card">
<h1>RAGNAR</h1><p>VPS Management Panel</p>{err}
<form method="post" action="{U('/login')}">
<label>Username</label><input name="username" autocomplete="username" required>
<label>Password</label><input name="password" type="password"
autocomplete="current-password" required>
<button class="btn" type="submit">Login</button></form>
</div></div></body></html>"""


def user_table(rows, kind, csrf):
    """Shared SSH/Xray user table with per-row actions."""
    head = ("<tr><th>User</th><th>Expires</th><th>Left</th><th>Used</th>"
            "<th>Quota</th><th>IP limit</th><th>Status</th><th></th></tr>")
    out = []
    for name, u in rows.items():
        live = u.get("live")
        if not u.get("enabled", True):
            status = '<span class="pill r">disabled</span>'
        elif live not in (None, "-", 0):
            status = f'<span class="pill g">online: {esc(live)}</span>'
        else:
            status = '<span class="pill b">active</span>'
        toggle = "enable" if not u.get("enabled", True) else "disable"
        links = (f'<a class="btn sm grey" href="{U("/xray/links")}?u={esc(name)}">Links</a> '
                 if kind == "xray" else "")
        out.append(
            f"<tr><td><b>{esc(name)}</b></td><td>{esc(u['expiry'])}</td>"
            f"<td>{esc(u['days_left'])}d</td><td>{esc(fmt_used(u))}</td>"
            f"<td>{esc(fmt_quota(u))}</td>"
            f"<td>{esc(u.get('ip_limit') or '∞')}</td><td>{status}</td>"
            f'<td style="white-space:nowrap">{links}'
            f'<a class="btn sm" href="{U("/" + kind + "/edit")}?u={esc(name)}">Edit</a> '
            f'<form class="inline" method="post" action="{U("/" + kind + "/action")}">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="user" value="{esc(name)}">'
            f'<button class="btn sm grey" name="op" value="{toggle}">{toggle}</button> '
            f'<button class="btn sm red" name="op" value="delete" '
            f'onclick="return confirm(\'Delete {esc(name)}?\')">delete</button>'
            f"</form></td></tr>")
    return (f'<div class="tblwrap"><table>{head}'
            f"{''.join(out) or '<tr><td>No users yet.</td></tr>'}</table></div>")


def add_user_form(kind, csrf):
    pw = ('<div><label>Password</label><input name="password" required></div>'
          if kind in ("ssh", "zivpn") else "")
    quota = ('<div><label>Quota GB (0 = unlimited)</label>'
             '<input name="quota" type="number" value="0" min="0"></div>'
             '<div><label>IP limit (0 = unlimited)</label>'
             '<input name="iplimit" type="number" value="0" min="0"></div>'
             if kind in ("ssh", "xray") else "")
    return f"""<form class="addform" method="post" action="{U('/' + kind + '/action')}">
<input type="hidden" name="csrf" value="{csrf}">
<div><label>Username</label><input name="user" required></div>{pw}
<div><label>Days</label><input name="days" type="number" value="30" min="1"></div>
{quota}<button class="btn" name="op" value="create" type="submit">+ Create user</button>
</form>"""



def page_dashboard(csrf, flash=""):
    info = server_info()
    stats = ragnar.stats()
    online = ragnar.online_users()
    bw = ragnar.bandwidth()
    today = bw.get("today") or {}
    month = bw.get("month") or {}
    cards = [
        ("Server IP", info["ip"], info["os"]),
        ("Uptime", info["uptime"], f"RAM {info['ram']}"),
        ("Disk", info["disk"], ""),
        ("Users", str(stats.get("total", 0)),
         f"SSH {stats.get('ssh', 0)} - Xray {stats.get('vless', 0)} - "
         f"ZIVPN {stats.get('zivpn', 0)}"),
        ("Online now", str(online.get("online", 0)), "SSH sessions + active Xray"),
        ("Bandwidth today", today.get("total_f", "n/a"),
         f"RX {today.get('rx_f', '-')} / TX {today.get('tx_f', '-')}"),
        ("Bandwidth month", month.get("total_f", "n/a"),
         f"RX {month.get('rx_f', '-')} / TX {month.get('tx_f', '-')}"),
    ]
    card_html = "".join(
        f'<div class="card"><div class="k">{esc(k)}</div>'
        f'<div class="v">{esc(v)}</div><div class="s">{esc(s)}</div></div>'
        for k, v, s in cards)
    svc = "".join(
        f'<tr><td>{esc(s)}</td><td><span class="dot '
        f'{"on-dot" if svc_active(s) else "off-dot"}"></span>'
        f'{"ONLINE" if svc_active(s) else "OFFLINE"}</td></tr>'
        for s in SERVICES)
    return layout("Dashboard", "dashboard",
                  f'<div class="cards">{card_html}</div>'
                  f'<h3>Services</h3><div class="tblwrap">'
                  f"<table>{svc}</table></div>", flash)


def page_users(kind, csrf, flash=""):
    titles = {"ssh": "SSH & SSL users", "xray": "Xray users",
              "zivpn": "ZIVPN users"}
    rows = ragnar._list_rows(kind)
    if kind == "zivpn":
        head = ("<tr><th>User</th><th>Expires</th><th>Left</th><th></th></tr>")
        body = "".join(
            f"<tr><td><b>{esc(n)}</b></td><td>{esc(u['expiry'])}</td>"
            f"<td>{esc(u['days_left'])}d</td>"
            f'<td style="white-space:nowrap">'
            f'<a class="btn sm" href="{U("/zivpn/edit")}?u={esc(n)}">Edit</a> '
            f'<form class="inline" method="post" action="{U("/zivpn/action")}">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="user" value="{esc(n)}">'
            f'<button class="btn sm red" name="op" value="delete" '
            f'onclick="return confirm(\'Delete {esc(n)}?\')">delete</button>'
            f"</form></td></tr>" for n, u in rows.items())
        table = (f'<div class="tblwrap"><table>{head}'
                 f"{body or '<tr><td>No users yet.</td></tr>'}</table></div>")
    else:
        table = user_table(rows, kind, csrf)
    return layout(titles[kind], kind, add_user_form(kind, csrf) + table, flash)


def page_edit(kind, user, csrf, flash=""):
    loaders = {"ssh": ragnar.load_ssh, "xray": ragnar.load_xray,
               "zivpn": ragnar.load_zivpn}
    users = loaders[kind]()
    if user not in users:
        return layout("Edit user", kind, f"<p>User '{esc(user)}' not found.</p>")
    u = users[user]
    left = ragnar.days_left(u["expiry"])
    used = (f"<p style='margin-top:4px'>Used so far: "
            f"<b>{esc(fmt_used(u))}</b></p>" if kind != "zivpn" else "")
    quota = ""
    if kind in ("ssh", "xray"):
        quota = f"""
<label>Quota GB (0 = unlimited)</label>
<input name="quota" type="number" step="any" min="0" value="{esc(u.get('quota_gb', 0))}">
<label>IP limit (0 = unlimited)</label>
<input name="iplimit" type="number" min="0" value="{esc(u.get('ip_limit', 0))}">"""
    password = ""
    if kind in ("ssh", "zivpn"):
        password = """
<label>New password (leave empty to keep the current one)</label>
<input name="password" type="text" autocomplete="off">"""
    enabled = "yes" if u.get("enabled", True) else "no"
    body = f"""<div class="card editform">
<div class="k">{esc(kind.upper())} user</div>
<div class="v">{esc(user)}</div>
<p>Expires: <b>{esc(u['expiry'])}</b> ({esc(left)} days left)</p>{used}
<form method="post" action="{U('/' + kind + '/edit')}">
<input type="hidden" name="csrf" value="{csrf}">
<input type="hidden" name="user" value="{esc(user)}">
<label>Add days (extends the current expiry)</label>
<input name="days" type="number" min="0" value="0">
{quota}{password}
<label>Enabled</label>
<select name="enabled">
<option value="yes" {'selected' if enabled == 'yes' else ''}>Yes</option>
<option value="no" {'selected' if enabled == 'no' else ''}>No</option>
</select>
<div style="margin-top:20px">
<button class="btn" type="submit">Save changes</button>
<a class="btn grey" href="{U('/' + kind)}">Back</a>
</div></form></div>"""
    return layout(f"Edit {user}", kind, body, flash)


def page_xray_links(user, csrf, flash=""):
    groups = ragnar.links_for(user)
    parts = [f"<h3>Links for {esc(user)}</h3>"]
    for group, items in groups.items():
        parts.append(f"<h3>{esc(group)}</h3>")
        for proto, uri in items.items():
            parts.append(
                f'<div><span class="pill b">{esc(proto)}</span> '
                f'<button class="btn sm grey" onclick="navigator.clipboard'
                f".writeText(document.getElementById('l{len(parts)}').innerText)"
                f'">Copy</button></div>'
                f'<div class="link-box" id="l{len(parts)}">{esc(uri)}</div>')
    return layout("Xray links", "xray", "".join(parts), flash)


def page_services(csrf, flash=""):
    rows = ""
    for s in SERVICES:
        on = svc_active(s)
        rows += (
            f'<tr><td>{esc(s)}</td><td><span class="dot '
            f'{"on-dot" if on else "off-dot"}"></span>'
            f'{"ONLINE" if on else "OFFLINE"}</td>'
            f'<td><form class="inline" method="post" action="{U("/services/restart")}">'
            f'<input type="hidden" name="csrf" value="{csrf}">'
            f'<input type="hidden" name="unit" value="{esc(s)}">'
            f'<button class="btn sm grey">Restart</button></form></td></tr>')
    st = ragnar.load_settings()
    slow = (f"<h3>SlowDNS</h3><table>"
            f"<tr><td>Nameserver</td><td>{esc(st.get('ns', '-'))}</td></tr>"
            f"<tr><td>Public key</td><td style='word-break:break-all'>"
            f"{esc(st.get('slowdns_pubkey', '-'))}</td></tr>"
            f"<tr><td>KCP Turbo</td><td>"
            f"{'ON' if st.get('slowdns_kcp') else 'OFF'}</td></tr></table>")
    return layout("Services", "services",
                  f'<div class="tblwrap"><table>{rows}</table></div>{slow}',
                  flash)


def page_settings(csrf, flash=""):
    cfg = load_web_cfg()
    body = f"""<div class="card" style="max-width:520px">
<form method="post" action="{U('/settings/password')}">
<input type="hidden" name="csrf" value="{csrf}">
<div class="k">Web panel login</div>
<p style="margin:10px 0">Username: <b>{esc(cfg['username'])}</b> -
Port: <b>{esc(cfg.get('port', DEFAULT_PORT))}</b></p>
<label style="font-size:12.5px;color:#94a3b8">Current password</label>
<input name="current" type="password" style="width:100%;margin:5px 0 12px" required>
<label style="font-size:12.5px;color:#94a3b8">New password</label>
<input name="new" type="password" style="width:100%;margin:5px 0 12px" required>
<label style="font-size:12.5px;color:#94a3b8">New username (optional)</label>
<input name="newuser" style="width:100%;margin:5px 0 16px"
value="{esc(cfg['username'])}">
<button class="btn" type="submit">Save</button></form></div>"""
    return layout("Settings", "settings", body, flash)


# ---------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------
def do_user_action(kind, form):
    op, user = form.get("op", ""), form.get("user", "").strip()
    if not user:
        return "Missing username."
    try:
        if op == "create":
            days = int(form.get("days", 30))
            if kind == "ssh":
                u = ragnar.ssh_add(user, form.get("password", ""), days,
                                   float(form.get("quota", 0)),
                                   int(form.get("iplimit", 0)))
                ragnar.sync_linux_user(user, u["password"], u["expiry"], True)
            elif kind == "xray":
                ragnar.xray_add(user, days, float(form.get("quota", 0)),
                                int(form.get("iplimit", 0)))
                ragnar.apply_configs()
            elif kind == "zivpn":
                ragnar.zivpn_add(user, form.get("password", ""), days)
                ragnar.apply_configs()
            return f"User '{user}' created."
        if op == "delete":
            if kind == "ssh":
                ragnar.ssh_del(user)
                ragnar._run(f"userdel -r {user} 2>/dev/null; true")
            elif kind == "xray":
                ragnar.xray_del(user)
                ragnar.apply_configs()
            elif kind == "zivpn":
                ragnar.zivpn_del(user)
                ragnar.apply_configs()
            return f"User '{user}' deleted."
        if op in ("enable", "disable"):
            enable = op == "enable"
            if kind == "ssh":
                u = ragnar.ssh_edit(user, enable=enable)
                ragnar.sync_linux_user(user, u["password"], u["expiry"], enable)
            elif kind == "xray":
                ragnar.xray_edit(user, enable=enable)
                ragnar.apply_configs()
            return f"User '{user}' {'enabled' if enable else 'disabled'}."
        if op == "renew30":
            if kind == "ssh":
                u = ragnar.ssh_edit(user, days=30, extend=True)
                ragnar.sync_linux_user(user, u["password"], u["expiry"],
                                       u.get("enabled", True))
            elif kind == "xray":
                ragnar.xray_edit(user, days=30, extend=True)
                ragnar.apply_configs()
            return f"User '{user}' extended by 30 days."
    except Exception as exc:  # surfaced to the admin as a flash message
        return f"Error: {exc}"
    return "Unknown action."


def do_edit(kind, form):
    user = form.get("user", "").strip()
    if not user:
        return "Missing username."
    try:
        days = int(form.get("days", 0))
        enable = form.get("enabled", "yes") == "yes"
        password = form.get("password", "")
        if kind == "ssh":
            kw = {"enable": enable}
            if days > 0:
                kw.update(days=days, extend=True)
            if "quota" in form:
                kw["quota_gb"] = float(form["quota"])
            if "iplimit" in form:
                kw["ip_limit"] = int(form["iplimit"])
            if password:
                kw["password"] = password
            u = ragnar.ssh_edit(user, **kw)
            ragnar.sync_linux_user(user, u["password"], u["expiry"],
                                   u.get("enabled", True))
        elif kind == "xray":
            kw = {"enable": enable}
            if days > 0:
                kw.update(days=days, extend=True)
            if "quota" in form:
                kw["quota_gb"] = float(form["quota"])
            if "iplimit" in form:
                kw["ip_limit"] = int(form["iplimit"])
            ragnar.xray_edit(user, **kw)
            ragnar.apply_configs()
        elif kind == "zivpn":
            kw = {"enable": enable}
            if days > 0:
                kw.update(days=days, extend=True)
            if password:
                kw["password"] = password
            ragnar.zivpn_edit(user, **kw)
            ragnar.apply_configs()
        return f"User '{user}' saved."
    except Exception as exc:  # surfaced to the admin as a flash message
        return f"Error: {exc}"


# ---------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):  # keep the journal quiet
        pass

    def _send(self, code, body, ctype="text/html; charset=utf-8", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, to, cookie=None):
        extra = {"Location": to}
        if cookie is not None:
            extra["Set-Cookie"] = cookie
        self._send(303, "", extra=extra)

    def _session(self):
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith("ragnar_session="):
                return check_session(part.split("=", 1)[1])
        return None

    def _session_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            part = part.strip()
            if part.startswith("ragnar_session="):
                return part.split("=", 1)[1]
        return ""

    def _form(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode()
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def _authed(self):
        if not self._session():
            self._redirect(U("/login"))
            return False
        return True

    def _route_path(self):
        p = urllib.parse.urlparse(self.path).path
        if BASE_PATH and (p == BASE_PATH or p.startswith(BASE_PATH + "/")):
            p = p[len(BASE_PATH):] or "/"
        return p

    def _csrf_ok(self, form):
        return hmac.compare_digest(form.get("csrf", ""),
                                   csrf_token(self._session_token()))

    def do_GET(self):
        path = self._route_path()
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        flash = qs.get("msg", [""])[0]
        if path == "/login":
            if self._session():
                return self._redirect(U("/"))
            return self._send(200, login_page())
        if path == "/logout":
            return self._redirect(
                U("/login"), "ragnar_session=; Max-Age=0; Path=/; HttpOnly")
        if not self._authed():
            return
        csrf = csrf_token(self._session_token())
        try:
            if path == "/":
                self._send(200, page_dashboard(csrf, flash))
            elif path in ("/ssh", "/xray", "/zivpn"):
                self._send(200, page_users(path[1:], csrf, flash))
            elif path in ("/ssh/edit", "/xray/edit", "/zivpn/edit"):
                self._send(200, page_edit(path.split("/")[1],
                                          qs.get("u", [""])[0], csrf, flash))
            elif path == "/xray/links":
                self._send(200, page_xray_links(qs.get("u", [""])[0], csrf, flash))
            elif path == "/services":
                self._send(200, page_services(csrf, flash))
            elif path == "/settings":
                self._send(200, page_settings(csrf, flash))
            else:
                self._send(404, "Not found")
        except Exception as exc:
            self._send(500, f"Error: {esc(exc)}")

    def do_POST(self):
        path = self._route_path()
        form = self._form()
        if path == "/login":
            ip = self.client_address[0]
            if login_locked(ip):
                return self._send(429, login_page("Too many attempts - wait 5 minutes."))
            if check_password(form.get("username", ""), form.get("password", "")):
                token = make_session(form["username"])
                secure = "; Secure" if self.server.tls else ""
                return self._redirect(
                    U("/"), f"ragnar_session={token}; Path=/; HttpOnly; "
                            f"SameSite=Lax; Max-Age={SESSION_TTL}{secure}")
            note_login_failure(ip)
            time.sleep(0.7)
            return self._send(401, login_page("Wrong username or password."))
        if not self._authed():
            return
        if not self._csrf_ok(form):
            return self._send(403, "Bad CSRF token - reload the page.")
        if path in ("/ssh/action", "/xray/action", "/zivpn/action"):
            kind = path.split("/")[1]
            msg = do_user_action(kind, form)
            return self._redirect(U(f"/{kind}") + "?msg=" + urllib.parse.quote(msg))
        if path in ("/ssh/edit", "/xray/edit", "/zivpn/edit"):
            kind = path.split("/")[1]
            msg = do_edit(kind, form)
            return self._redirect(U(f"/{kind}") + "?msg=" + urllib.parse.quote(msg))
        if path == "/services/restart":
            unit = form.get("unit", "")
            if unit in SERVICES:
                subprocess.run(["systemctl", "restart", unit],
                               capture_output=True)
                return self._redirect(
                    U("/services") + "?msg=" + urllib.parse.quote(unit + " restarted"))
            return self._send(400, "Unknown service")
        if path == "/settings/password":
            if not check_password(load_web_cfg()["username"],
                                  form.get("current", "")):
                return self._redirect(U("/settings") + "?msg=Current password is wrong")
            newuser = form.get("newuser", "").strip() or load_web_cfg()["username"]
            set_password(newuser, form["new"])
            return self._redirect(
                U("/login"), "ragnar_session=; Max-Age=0; Path=/; HttpOnly")
        self._send(404, "Not found")


def serve():
    cfg = load_web_cfg()
    port = int(os.environ.get("RAGNAR_WEB_PORT", cfg.get("port", DEFAULT_PORT)))
    bind = os.environ.get("RAGNAR_WEB_BIND", "0.0.0.0")
    httpd = ThreadingHTTPServer((bind, port), Handler)
    httpd.tls = False
    ctx = None
    if not os.environ.get("RAGNAR_WEB_NO_TLS"):
        cert = os.path.join(BASE, "certs", "fullchain.pem")
        key = os.path.join(BASE, "certs", "privkey.pem")
        combo = os.path.join(BASE, "certs", "haproxy.pem")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            if os.path.exists(cert) and os.path.exists(key):
                ctx.load_cert_chain(cert, key)
            elif os.path.exists(combo):
                ctx.load_cert_chain(combo, combo)
            else:
                ctx = None
        except ssl.SSLError:
            ctx = None
    if ctx is not None:
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        httpd.tls = True
    print(f"Ragnar web panel on {bind}:{port}{BASE_PATH} "
          f"({'HTTPS' if httpd.tls else 'HTTP'})", flush=True)
    httpd.serve_forever()


def _random_password():
    return secrets.token_urlsafe(12)


if __name__ == "__main__":
    args = sys.argv[1:]
    if args[:1] == ["--init"]:
        cfg = load_web_cfg()
        if "hash" in cfg:
            print(f"Web login already set for user '{cfg['username']}'. "
                  "Use --reset-password to change it.")
        else:
            pw = _random_password()
            set_password(cfg["username"], pw)
            print(f"Web panel login created - user: {cfg['username']}  "
                  f"password: {pw}")
            print("Save it now; change it later in Settings or with "
                  "--reset-password.")
    elif args[:1] == ["--reset-password"]:
        cfg = load_web_cfg()
        pw = _random_password()
        set_password(cfg["username"], pw)
        print(f"Web panel password reset - user: {cfg['username']}  "
              f"new password: {pw}")
    elif args[:1] == ["--set-password"] and len(args) == 3:
        set_password(args[1], args[2])
        print(f"Web panel login set for user '{args[1]}'.")
    else:
        serve()
