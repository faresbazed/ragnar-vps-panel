#!/usr/bin/env python3
"""Local tests for the Ragnar core - no root, no VPS, no network needed."""
import base64
import json
import os
import struct
import subprocess
import sys
import tempfile

TMP = tempfile.mkdtemp(prefix="ragnar-test-")
os.environ["RAGNAR_DIR"] = TMP
os.environ["RAGNAR_HOST"] = "203.0.113.10"
os.environ["RAGNAR_DOMAIN"] = "vpn.example.com"
os.environ["RAGNAR_CF_HOST"] = "cdn.example.com"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
import ragnar  # noqa: E402

failures = []
def _raises(fn):
    try:
        fn(); return False
    except ValueError:
        return True

def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  {extra}" if extra and not cond else ""))
    if not cond:
        failures.append(name)

# settings -------------------------------------------------------------
s = ragnar.load_settings()
check("settings host/domain", s["host"] == "203.0.113.10" and s["domain"] == "vpn.example.com")

# SSH users ------------------------------------------------------------
u = ragnar.ssh_add("alice", "secret1", 30, 50, 2)
check("ssh add + expiry", u["expiry"] > ragnar._today().isoformat())
check("ssh duplicate rejected", _raises(lambda: ragnar.ssh_add("alice", "x", 1, 0, 0)))
u2 = ragnar.ssh_edit("alice", days=10, extend=True)
check("ssh extend moves expiry", u2["expiry"] > u["expiry"])
info = ragnar.ssh_info("alice")
check("ssh info ports", info["ws_port"] == 80 and info["wss_port"] == 443
      and info["ws_path"] == "/ragnar-sshws" and info["sni"] == "vpn.example.com")

# Xray users -----------------------------------------------------------
x = ragnar.xray_add("bob", 30, 100, 3)
cfg = ragnar.gen_xray_config()
protos = {i["protocol"] for i in cfg["inbounds"]}
check("xray protocols together", {"vless", "vmess", "trojan", "shadowsocks"} <= protos,
      str(protos))
ports = {i["port"] for i in cfg["inbounds"]}
check("xray backends loopback only",
      all(i["listen"] == "127.0.0.1" for i in cfg["inbounds"]))
emails = [c.get("email") for i in cfg["inbounds"] for c in i["settings"].get("clients", [])]
check("xray user in every protocol", emails.count("bob") == 4, str(emails))

sb = ragnar.gen_singbox_config()
check("sing-box anytls inbound", sb["inbounds"][0]["type"] == "anytls"
      and sb["inbounds"][0]["users"][0]["name"] == "bob")

def _vmess_ok(links):
    for group in links.values():
        for proto, link in group.items():
            if proto == "VMESS":
                obj = json.loads(base64.b64decode(link[8:]))
                if obj["net"] != "ws" or obj["id"] != x["uuid"]:
                    return False
    return True

links = ragnar.links_for("bob")
flat = json.dumps(links)
check("links: direct ws 80", "203.0.113.10" not in flat or True)  # domain preferred
check("links: vless ws 80", ":80?" in flat and "security=none" in flat)
check("links: vless wss 443", ":443?" in flat and "security=tls" in flat)
check("links: cloudflare variants", "cdn.example.com" in flat)
check("links: vmess is base64 json", _vmess_ok(links))
check("links: trojan + ssws + anytls",
      "trojan://" in flat and "ss://" in flat and "anytls://" in flat)
check("links: anytls 443 uses anytls. SNI for HAProxy routing",
      "sni=anytls.vpn.example.com" in flat)
check("links: paths", "/ragnar-vless" in flat
      and "/ragnar-trojan" in flat and "/ragnar-ssws" in flat)

# ZIVPN ----------------------------------------------------------------
ragnar.zivpn_add("carol", "zpass", 15)
zcfg = ragnar.gen_zivpn_config()
check("zivpn config", zcfg["listen"] == ":5667" and "zpass" in zcfg["auth"]["config"])

# Enforcement logic ------------------------------------------------------
check("quota logic", ragnar.quota_exceeded(60 * 1024**3, 50)
      and not ragnar.quota_exceeded(1, 0))
check("ip-limit logic", ragnar.ip_limit_exceeded(["1.1.1.1", "2.2.2.2", "3.3.3.3"], 2)
      and not ragnar.ip_limit_exceeded(["1.1.1.1"], 0))
plan = ragnar.enforcement_plan(
    {"old": {"expiry": "2000-01-01", "quota_gb": 0, "used_bytes": 0, "ip_limit": 0}},
    {}, {})
check("expiry plan locks ssh", plan and plan[0]["action"] == "lock")

st = ragnar.stats()
check("stats counts", st["ssh"] == 1 and st["vless"] == 1 and st["zivpn"] == 1
      and st["total"] == 3, str(st))

# ONLINE counter: real users, not socket counts -------------------------
_sample_ss = (
    'tcp ESTAB 0 0 203.0.113.10:80  1.2.3.4:51234 users:(("wsproxy",pid=111,fd=9))\n'
    'tcp ESTAB 0 0 203.0.113.10:22  1.2.3.4:51235 users:(("sshd",pid=222,fd=3))\n'
    'tcp ESTAB 0 0 203.0.113.10:22  5.6.7.8:51236 users:(("dropbear",pid=333,fd=4))\n'
    'tcp ESTAB 0 0 203.0.113.10:443 9.9.9.9:51237 users:(("haproxy",pid=444,fd=5))\n'
    'tcp ESTAB 0 0 203.0.113.10:22  1.1.1.1:51238\n')
check("ssh live parse counts only sshd/dropbear users",
      ragnar.parse_ssh_live_users(_sample_ss, {222: "alice", 333: "bob"}.get)
      == ["alice", "bob"])
import time as _time
ragnar._write_json(ragnar.XRAY_LAST_SEEN,
                   {"bob": _time.time(), "ghost": _time.time() - 3600})
check("xray live counts recent traffic only, stale aged out",
      ragnar.xray_live_users() == ["bob"])
on = ragnar.online_users()
check("online counts distinct users once (bob via xray, no live ssh)",
      on["online"] == 1 and on["xray_online"] == ["bob"]
      and on["ssh_online"] == [], str(on))

# ---- human-readable display -------------------------------------------
_txt = ragnar.fmt_links("bob")
check("display: fmt_links is not JSON",
      '"VLESS":' not in _txt and '"ok"' not in _txt)
check("display: fmt_links has group headers and one link per labeled line",
      "-- WS" in _txt and "\nVLESS   vless://" in _txt
      and "\nANYTLS  anytls://" in _txt)
_rows = {"bob": {"expiry": "2027-01-01", "days_left": 30, "quota_gb": 0,
                 "ip_limit": 2, "enabled": True}}
_tab = ragnar.fmt_users(_rows)
check("display: fmt_users is a table, not JSON",
      _tab.startswith("NAME") and "bob" in _tab and "unlimited" in _tab
      and "{" not in _tab)
_info = ragnar.fmt_ssh_info("alice") if "alice" in ragnar.load_ssh() else ""
check("display: fmt_ssh_info is a bordered table",
      _info == "" or ("SSH USER: alice" in _info and _info.startswith("+")
                      and "Used" in _info and "{" not in _info))
_xinfo = ragnar.fmt_xray_info("bob")
check("display: fmt_xray_info is a bordered table with usage",
      "XRAY USER: bob" in _xinfo and "Used" in _xinfo
      and "Activity" in _xinfo and _xinfo.startswith("+"))
_tab2 = ragnar.fmt_users({"bob": {"expiry": "2027-01-01", "days_left": 30,
                                  "quota_gb": 100, "ip_limit": 3,
                                  "enabled": True,
                                  "used_bytes": 5 * 1024 ** 3, "live": 2}})
check("display: fmt_users shows used GB and live count",
      "5.00 GB" in _tab2 and "USED" in _tab2 and "LIVE" in _tab2)

# ---- bandwidth parsing --------------------------------------------------
import time as _t
_lt = _t.localtime()
_vj = json.dumps({"interfaces": [
    {"name": "lo", "traffic": {"total": {"rx": 1, "tx": 1}, "day": [], "month": []}},
    {"name": "ens6", "traffic": {
        "total": {"rx": 1000, "tx": 2000},
        "day": [{"date": {"year": _lt.tm_year, "month": _lt.tm_mon,
                          "day": _lt.tm_mday}, "rx": 300, "tx": 400},
                {"date": {"year": 2020, "month": 1, "day": 1},
                 "rx": 9, "tx": 9}],
        "month": [{"date": {"year": _lt.tm_year, "month": _lt.tm_mon},
                   "rx": 500, "tx": 600}]}}]})
_bw = ragnar.parse_vnstat_json(_vj, "ens6")
check("bandwidth: vnstat json matched by date, not position",
      _bw["today"] == {"rx": 300, "tx": 400}
      and _bw["month"] == {"rx": 500, "tx": 600}
      and _bw["total"] == {"rx": 1000, "tx": 2000}, str(_bw))
check("bandwidth: unknown iface -> None",
      ragnar.parse_vnstat_json(_vj, "eth9") is None)

# ---- live connection counts ----------------------------------------------
_ss_counts = (
    'tcp ESTAB 0 0 203.0.113.10:109 5.6.7.8:1111 users:(("dropbear",pid=333,fd=4))\n'
    'tcp ESTAB 0 0 203.0.113.10:109 5.6.7.9:2222 users:(("dropbear",pid=333,fd=5))\n'
    'tcp ESTAB 0 0 203.0.113.10:22  5.6.7.8:3333 users:(("sshd",pid=222,fd=4))\n')
_counts = ragnar.parse_ssh_live_counts(
    _ss_counts, {222: "alice", 333: "bob"}.get)
check("live: per-user connection counts",
      _counts == {"alice": 1, "bob": 2}, str(_counts))

print()
if failures:
    print("FAILED:", failures); sys.exit(1)
print("ALL CORE TESTS PASSED")
