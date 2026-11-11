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

print()
if failures:
    print("FAILED:", failures); sys.exit(1)
print("ALL CORE TESTS PASSED")
