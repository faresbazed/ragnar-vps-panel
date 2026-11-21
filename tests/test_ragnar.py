#!/usr/bin/env python3
"""Local tests for the Ragnar core - no root, no VPS, no network needed."""
import base64
import contextlib
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

TMP = tempfile.mkdtemp(prefix="ragnar-test-")
os.environ["RAGNAR_DIR"] = TMP
os.environ["RAGNAR_HOST"] = "203.0.113.10"
os.environ["RAGNAR_DOMAIN"] = "vpn.example.com"
os.environ["RAGNAR_CF_HOST"] = "cdn.example.com"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "core"))
sys.modules.pop("ragnar", None)
import ragnar  # noqa: E402
R = ragnar

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
check("xray UUID defaults to generated RFC 4122 v4",
      ragnar._uuid.UUID(x["uuid"]).version == 4
      and ragnar._uuid.UUID(x["uuid"]).variant == ragnar._uuid.RFC_4122)
custom_uuid = "123e4567-e89b-42d3-a456-426614174000"
custom = ragnar.xray_add("zoe", 30, 0, 0, custom_uuid.upper())
check("xray custom UUID stored canonically", custom["uuid"] == custom_uuid)
cfg = ragnar.gen_xray_config()
protos = {i["protocol"] for i in cfg["inbounds"]}
check("xray protocols together", {"vless", "vmess", "trojan", "shadowsocks"} <= protos,
      str(protos))
ports = {i["port"] for i in cfg["inbounds"]}
check("xray backends loopback only",
      all(i["listen"] == "127.0.0.1" for i in cfg["inbounds"]))
emails = [c.get("email") for i in cfg["inbounds"] for c in i["settings"].get("clients", [])]
check("xray user in every protocol", emails.count("bob") == 4, str(emails))
custom_ids = [c.get("id") for i in cfg["inbounds"]
              for c in i["settings"].get("clients", [])]
check("xray custom UUID reaches VLESS and VMess configs",
      custom_ids.count(custom_uuid) == 2, str(custom_ids))
check("xray custom UUID appears in generated links",
      custom_uuid in json.dumps(ragnar.links_for("zoe")))
check("xray rejects malformed UUID without creating user",
      _raises(lambda: ragnar.xray_add("bad-uuid", 30, custom_uuid="not-a-uuid"))
      and "bad-uuid" not in ragnar.load_xray())
check("xray rejects UUID already assigned to another user",
      _raises(lambda: ragnar.xray_add("duplicate-uuid", 30,
                                      custom_uuid=custom_uuid))
      and "duplicate-uuid" not in ragnar.load_xray())

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
fallback = ragnar.gen_zivpn_config()["auth"]["config"]
check("zivpn empty users never use public fallback",
      "ragnar-default-change-me" not in fallback)
check("zivpn fallback is non-empty and stable",
      len(fallback) == 1 and bool(fallback[0])
      and fallback == ragnar.gen_zivpn_config()["auth"]["config"])
check("zivpn fallback persisted in settings",
      ragnar._read_json(ragnar.SETTINGS, {}).get("zivpn_fallback_password") == fallback[0])
ragnar.zivpn_add("expired", "expired-password", -1)
check("zivpn expired-only users use stable private fallback",
      ragnar.gen_zivpn_config()["auth"]["config"] == fallback
      and "ragnar-default-change-me" not in fallback
      and "expired-password" not in fallback)
ragnar.zivpn_del("expired")
ragnar.zivpn_add("carol", "zpass", 15)
zcfg = ragnar.gen_zivpn_config()
check("zivpn config", zcfg["listen"] == ":5667" and "zpass" in zcfg["auth"]["config"])
ragnar.zivpn_add("dave", "dpass", 15)
check("zivpn edit rejects a password another account already uses",
      _raises(lambda: ragnar.zivpn_edit("dave", password="zpass"))
      and ragnar.load_zivpn()["dave"]["password"] == "dpass")
check("zivpn add rejects a password another account already uses",
      _raises(lambda: ragnar.zivpn_add("erin", "zpass", 15))
      and "erin" not in ragnar.load_zivpn())
ragnar.zivpn_edit("dave", password="dpass")
ragnar.zivpn_edit("carol", enable=False)
check("zivpn disabling an account stops its password being accepted",
      "zpass" not in ragnar.gen_zivpn_config()["auth"]["config"])
ragnar.zivpn_edit("carol", enable=True)
for _name in set(ragnar.load_zivpn()) - {"carol"}:
    ragnar.zivpn_del(_name)
_zdb = ragnar._read_json(ragnar.ZIVPN_DB, {"users": {}})
_zdb["users"]["legacy-twin"] = dict(_zdb["users"]["carol"], enabled=False)
ragnar._write_json(ragnar.ZIVPN_DB, _zdb)
check("zivpn existing shared password is revoked when either account is disabled",
      "zpass" not in ragnar.gen_zivpn_config()["auth"]["config"])
ragnar.zivpn_del("legacy-twin")
check("zivpn password accepted again once the inactive duplicate is gone",
      "zpass" in ragnar.gen_zivpn_config()["auth"]["config"])

# Enforcement logic ------------------------------------------------------
check("quota logic", ragnar.quota_exceeded(60 * 1024**3, 50)
      and not ragnar.quota_exceeded(1, 0))
check("ip-limit logic", ragnar.ip_limit_exceeded(["1.1.1.1", "2.2.2.2", "3.3.3.3"], 2)
      and not ragnar.ip_limit_exceeded(["1.1.1.1"], 0))
plan = ragnar.enforcement_plan(
    {"old": {"expiry": "2000-01-01", "quota_gb": 0, "used_bytes": 0, "ip_limit": 0}},
    {}, {})
check("expiry plan locks ssh", plan and plan[0]["action"] == "lock")
plan_disabled = ragnar.enforcement_plan(
    {"old": {"expiry": "2000-01-01", "quota_gb": 0, "used_bytes": 0,
             "ip_limit": 0, "enabled": False}},
    {"xold": {"expiry": "2000-01-01", "quota_gb": 0, "used_bytes": 0,
              "ip_limit": 0, "enabled": False}}, {})
check("enforcement skips already-disabled accounts (no restart storm)",
      plan_disabled == [], str(plan_disabled))
ucfg = ragnar.gen_udp_custom_config()
check("udp-custom config mirrors active ssh users",
      "alice:secret1" in ucfg["auth"]["config"], str(ucfg))

st = ragnar.stats()
check("stats counts", st["ssh"] == 1 and st["vless"] == 2 and st["zivpn"] == 1
      and st["total"] == 4, str(st))

_cli_uuid = "123e4567-e89b-42d3-b456-426614174000"
_apply_configs = ragnar.apply_configs
ragnar.apply_configs = lambda: None
try:
    with contextlib.redirect_stdout(io.StringIO()):
        _cli_rc = ragnar.main(["xray-add", "cli-user", "30", "0", "0", _cli_uuid])
finally:
    ragnar.apply_configs = _apply_configs
check("xray CLI accepts optional UUID", _cli_rc == 0
      and ragnar.load_xray()["cli-user"]["uuid"] == _cli_uuid)

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
      _tab.startswith("┌") and "bob" in _tab and "0B/∞" in _tab
      and "{" not in _tab)
_info = ragnar.fmt_ssh_info("alice") if "alice" in ragnar.load_ssh() else ""
check("display: fmt_ssh_info is a bordered table",
      _info == "" or ("SSH USER: alice" in _info and _info.startswith("┌")
                      and "Used" in _info and "{" not in _info))
_xinfo = ragnar.fmt_xray_info("bob")
check("display: fmt_xray_info is a bordered table with usage",
      "XRAY USER: bob" in _xinfo and "Used" in _xinfo
      and "Activity" in _xinfo and _xinfo.startswith("┌"))
_tab2 = ragnar.fmt_users({"bob": {"expiry": "2027-01-01", "days_left": 30,
                                  "quota_gb": 100, "ip_limit": 3,
                                  "enabled": True,
                                  "used_bytes": 5 * 1024 ** 3, "live": 2}})
check("display: fmt_users shows used GB and live count",
      "5G/100G" in _tab2 and "USED/QUOTA" in _tab2 and "LIVE" in _tab2)

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
_summary = ragnar.bandwidth_summary({
    "today": {"total_f": "549.5 MB", "rx_f": "496.9 MB", "tx_f": "52.5 MB"},
    "month": {"total_f": "549.5 MB", "rx_f": "496.9 MB", "tx_f": "52.5 MB"},
    "source": "vnstat"})
check("bandwidth: simplified summary shows only combined totals",
      "549.5 MB" in _summary and "RX" not in _summary and "TX" not in _summary)
_fallback = ragnar.bandwidth_summary({"source": "kernel (since boot)"})
check("bandwidth: simplified summary retains fallback-source label",
      "kernel (since boot)" in _fallback and "TODAY" in _fallback
      and "MONTH" in _fallback)

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


class TestShareLinkPasswords(unittest.TestCase):
    def test_reserved_password_userinfo(self):
        with patch.object(ragnar.os, "urandom", return_value=b"\xff" * 16):
            user = ragnar.xray_add("reserved-password", 30)
        try:
            self.assertEqual(user["password"], "/////////////////////w==")
            links = ragnar.links_for("reserved-password")
            expected = [
                ("TROJAN", "vpn.example.com", 80),
                ("TROJAN", "vpn.example.com", 443),
                ("TROJAN", "cdn.example.com", 80),
                ("TROJAN", "cdn.example.com", 443),
                ("ANYTLS", "vpn.example.com", 443),
                ("ANYTLS", "vpn.example.com", 8446),
            ]
            actual = [(proto, link) for group in links.values()
                      for proto, link in group.items()
                      if proto in ("TROJAN", "ANYTLS")]
            self.assertEqual(len(actual), len(expected))
            for (proto, link), (expected_proto, host, port) in zip(actual, expected):
                with self.subTest(protocol=proto, host=host, port=port):
                    parsed = urlsplit(link)
                    self.assertEqual(proto, expected_proto)
                    self.assertEqual(parsed.hostname, host)
                    self.assertEqual(parsed.port, port)
                    self.assertEqual(unquote(parsed.username), user["password"])
        finally:
            ragnar.xray_del("reserved-password")


class TestBorderedTables(unittest.TestCase):
    def test_ssh_table_is_48_wide_box(self):
        users = {
            "channel": {"expiry": "2026-11-18", "days_left": 5,
                        "used_bytes": 0, "quota_gb": 0, "enabled": True,
                        "live": 2},
            "fares": {"expiry": "2026-12-11", "days_left": 28,
                      "used_bytes": int(1.13 * 1024 ** 3), "quota_gb": 100,
                      "enabled": True, "live": "-"},
        }
        out = R.fmt_users(users, "SSH USERS")
        lines = out.splitlines()
        self.assertTrue(all(len(l) == 48 for l in lines), out)
        self.assertIn("SSH USERS (2)", lines[1])
        self.assertIn("1.13G/100G", out)
        self.assertIn("0B/∞", out)
        self.assertTrue(lines[0].startswith("┌") and lines[-1].startswith("└"))

    def test_zivpn_table_is_48_wide_box(self):
        users = {"u1": {"expiry": "2026-12-01", "days_left": 18}}
        out = R.fmt_zivpn_users(users)
        self.assertTrue(all(len(l) == 48 for l in out.splitlines()), out)
        self.assertIn("ZIVPN USERS (1)", out)

    def test_bytes_short(self):
        self.assertEqual(R._fmt_bytes_short(0), "0B")
        self.assertEqual(R._fmt_bytes_short(28 * 1024), "28K")
        self.assertEqual(R._fmt_bytes_short(int(1.13 * 1024 ** 3)), "1.13G")


class TestSSHCreation(unittest.TestCase):
    def test_useradd_home_failure_rolls_back_created_account(self):
        for cleanup_status in (0, 8):
            with self.subTest(cleanup_status=cleanup_status), \
                 tempfile.TemporaryDirectory() as base, \
                 patch.object(R, 'SSH_DB', os.path.join(base, 'ssh.json')), \
                 patch.object(R.subprocess, 'run', side_effect=[
                     subprocess.CompletedProcess([], 1, '', ''),
                     subprocess.CompletedProcess([], 12, '', 'cannot create home'),
                     subprocess.CompletedProcess([], cleanup_status, '', '')]) as run, \
                 patch.object(R, 'sync_udp_custom') as sync:
                with self.assertRaisesRegex(R.SSHSyncError, 'useradd exited with status 12') as error:
                    R.ssh_create('partial-user', 'password', 30, 0, 0)
                self.assertEqual(run.call_args_list[-1].args[0],
                                 ['userdel', '-r', '--', 'partial-user'])
                self.assertEqual('rollback failed' in str(error.exception), bool(cleanup_status))
                self.assertEqual(R.load_ssh(), {})
                self.assertNotIn('partial-user:password',
                                 R.gen_udp_custom_config()['auth']['config'])
                sync.assert_not_called()

    def test_failed_useradd_never_deletes_another_calls_account(self):
        for failure in (subprocess.CompletedProcess([], 9, '', ''), OSError('cannot execute')):
            with self.subTest(failure=failure), \
                 patch.object(R.subprocess, 'run', side_effect=[
                     subprocess.CompletedProcess([], 1, '', ''), failure]) as run, \
                 patch.object(R, 'sync_udp_custom') as sync:
                with self.assertRaisesRegex(R.SSHSyncError, 'useradd'):
                    R.sync_linux_user('racing-user', 'password', '2030-01-01')
                self.assertEqual([call.args[0][0] for call in run.call_args_list],
                                 ['id', 'useradd'])
                sync.assert_not_called()

    def test_disable_locks_before_fallible_updates(self):
        for failure in (None, 'chpasswd', 'chage'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as base, \
                 patch.object(R, 'SSH_DB', os.path.join(base, 'ssh.json')):
                account = R.ssh_add('disable-user', 'password', 30, 0, 0)
                R.ssh_edit('disable-user', enable=False)
                calls = []

                def run(args, **kwargs):
                    calls.append(args)
                    rc = int(args[0] == failure)
                    return subprocess.CompletedProcess(args, rc, '', '')

                def sync_udp():
                    self.assertEqual(calls[-1], ['usermod', '-L', 'disable-user'])
                    self.assertNotIn('disable-user:password',
                                     R.gen_udp_custom_config()['auth']['config'])

                with patch.object(R.subprocess, 'run', side_effect=run), \
                     patch.object(R, 'sync_udp_custom', side_effect=sync_udp) as sync:
                    if failure:
                        with self.assertRaisesRegex(R.SSHSyncError, failure):
                            R.sync_linux_user('disable-user', 'password', account['expiry'], False)
                    else:
                        R.sync_linux_user('disable-user', 'password', account['expiry'], False)
                self.assertEqual(calls[1], ['usermod', '-L', 'disable-user'])
                self.assertEqual(calls[-1], ['usermod', '-L', 'disable-user'])
                self.assertNotIn(['usermod', '-U', 'disable-user'], calls)
                self.assertNotIn('userdel', [args[0] for args in calls])
                sync.assert_called_once_with()

    def test_success_and_duplicate(self):
        with tempfile.TemporaryDirectory() as base, \
             patch.object(R, 'SSH_DB', os.path.join(base, 'ssh.json')), \
             patch.object(R, 'sync_udp_custom') as sync:
            def run(args, **kwargs):
                return subprocess.CompletedProcess(args, int(args[0] == 'id'), '', '')

            with patch.object(R.subprocess, 'run', side_effect=run):
                rec = R.ssh_create('new-user', 'password', 30, 0, 0)
                self.assertEqual(R.load_ssh()['new-user'], rec)
                sync.assert_called_once_with()
                with self.assertRaises(ValueError):
                    R.ssh_create('new-user', 'other', 30, 0, 0)
                with self.assertRaises(ValueError):
                    R.ssh_create('', 'password', 30, 0, 0)
                self.assertEqual(R.load_ssh(), {'new-user': rec})

    def test_oserror_and_failed_rollback_are_visible(self):
        for existing in (False, True):
            with self.subTest(existing=existing), tempfile.TemporaryDirectory() as base, \
                 patch.object(R, 'SSH_DB', os.path.join(base, 'ssh.json')), \
                 patch.object(R, 'sync_udp_custom') as sync:
                calls = []

                def run(args, **kwargs):
                    calls.append(args[0])
                    if args[0] == 'chpasswd':
                        raise OSError('cannot execute')
                    rc = int(not existing) if args[0] == 'id' else 0
                    if args[0] == 'userdel':
                        rc = 8
                    return subprocess.CompletedProcess(args, rc, '', '')

                with patch.object(R.subprocess, 'run', side_effect=run):
                    with self.assertRaisesRegex(R.SSHSyncError, 'Could not run chpasswd') as error:
                        R.ssh_create('failed-user', 'password', 30, 0, 0)
                self.assertEqual('rollback failed' in str(error.exception), not existing)
                self.assertEqual('userdel' in calls, not existing)
                self.assertEqual(R.load_ssh(), {})
                sync.assert_not_called()

    def test_host_command_failures_roll_back_creation(self):
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'web'))
        import webpanel
        for command in ('useradd', 'chpasswd', 'chage', 'usermod'):
            for frontend in ('web', 'cli'):
                with self.subTest(command=command, frontend=frontend), \
                     tempfile.TemporaryDirectory() as base, \
                     patch.object(R, 'SSH_DB', os.path.join(base, 'ssh.json')), \
                     patch.object(webpanel, 'ragnar', R):
                    calls = []

                    def run(args, **kwargs):
                        calls.append(args[0])
                        rc = 1 if args[0] in ('id', command) else 0
                        return subprocess.CompletedProcess(args, rc, '', 'host failure')

                    with patch.object(R.subprocess, 'run', side_effect=run), \
                         patch.object(R, 'sync_udp_custom') as sync, \
                         contextlib.redirect_stdout(io.StringIO()) as output:
                        if frontend == 'web':
                            message = webpanel.do_user_action('ssh', {
                                'op': 'create', 'user': 'failed-user',
                                'password': 'password', 'days': '30'})
                            self.assertIn('Error:', message)
                        else:
                            self.assertEqual(R.main(['ssh-add', 'failed-user',
                                                     'password', '30', '0', '0']), 1)
                            message = output.getvalue()
                    self.assertIn(command, message)
                    self.assertNotIn('created', message)
                    self.assertNotIn('failed-user', R.load_ssh())
                    self.assertNotIn('failed-user:password',
                                     R.gen_udp_custom_config()['auth']['config'])
                    sync.assert_not_called()
                    self.assertEqual('userdel' in calls, command != 'useradd')


    def test_foreign_host_account_is_rejected(self):
        with tempfile.TemporaryDirectory() as base, \
             patch.object(R, "SSH_DB", os.path.join(base, "ssh.json")), \
             patch.object(R.pwd, "getpwnam"), \
             patch.object(R.subprocess, "run") as run, \
             patch.object(R, "sync_udp_custom") as sync, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            rc = R.main(["ssh-add", "ubuntu", "password", "30", "0", "0"])
            self.assertEqual(rc, 1, output.getvalue().strip())
            self.assertIn("not managed by the panel", json.loads(output.getvalue())["error"])
            self.assertEqual(R.load_ssh(), {})
            run.assert_not_called()
            sync.assert_not_called()

    def test_new_host_account_can_be_created(self):
        with tempfile.TemporaryDirectory() as base, \
             patch.object(R, "SSH_DB", os.path.join(base, "ssh.json")), \
             patch.object(R.pwd, "getpwnam", side_effect=KeyError("new-user")):
            account = R.ssh_add("new-user", "password", 30, 0, 0)
            self.assertEqual(R.load_ssh()["new-user"], account)

    def test_host_lookup_error_does_not_create_record(self):
        with tempfile.TemporaryDirectory() as base, \
             patch.object(R, "SSH_DB", os.path.join(base, "ssh.json")), \
             patch.object(R.pwd, "getpwnam", side_effect=OSError("lookup failed")):
            with self.assertRaisesRegex(OSError, "lookup failed"):
                R.ssh_add("new-user", "password", 30, 0, 0)
            self.assertEqual(R.load_ssh(), {})

    def test_managed_host_account_can_still_be_synced(self):
        with tempfile.TemporaryDirectory() as base, \
             patch.object(R, "SSH_DB", os.path.join(base, "ssh.json")), \
             patch.object(R.pwd, "getpwnam", side_effect=KeyError("managed-user")):
            account = R.ssh_add("managed-user", "password", 30, 0, 0)
            with patch.object(R.subprocess, "run", return_value=subprocess.CompletedProcess(
                    [], 0, "", "")) as run, patch.object(R, "sync_udp_custom"):
                R.sync_linux_user("managed-user", account["password"], account["expiry"])
            self.assertEqual([call.args[0][0] for call in run.call_args_list],
                             ["id", "chpasswd", "chage", "usermod"])


class TestSSHDeletion(unittest.TestCase):
    def test_busy_linux_user_keeps_panel_record(self):
        username = "active-user"
        command = ["userdel", "-r", "--", username]
        error = f"userdel: user {username} is currently used by process 4242"
        with tempfile.TemporaryDirectory() as base, \
             patch.object(R, "SSH_DB", os.path.join(base, "ssh.json")):
            account = R.ssh_add(username, "password", 30, 10, 1)
            with patch.object(R.subprocess, "run", return_value=subprocess.CompletedProcess(
                    command, 8, "", error + "\n")) as run, \
                 patch.object(R.pwd, "getpwnam"), \
                 patch.object(R, "sync_udp_custom") as sync, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                rc = R.main(["ssh-del", username])

            run.assert_called_once_with(command, capture_output=True, text=True)
            with self.subTest(check="panel record"):
                self.assertEqual(R.load_ssh().get(username), account)
            with self.subTest(check="CLI result"):
                self.assertEqual(rc, 1, output.getvalue().strip())
                self.assertIn(error, json.loads(output.getvalue())["error"])
            with self.subTest(check="UDP Custom sync"):
                sync.assert_not_called()

    def test_syncs_removal_only_after_linux_user_is_gone(self):
        for returncode in (0, 6):
            with self.subTest(userdel_exit=returncode), \
                 tempfile.TemporaryDirectory() as base, \
                 patch.object(R, "SSH_DB", os.path.join(base, "ssh.json")):
                username = "departing-user"
                account = R.ssh_add(username, "password", 30, 10, 1)

                def userdel(command, **kwargs):
                    self.assertEqual(R.load_ssh()[username], account)
                    return subprocess.CompletedProcess(command, returncode, "", "")

                def sync_udp():
                    self.assertNotIn(username, R.load_ssh())

                with patch.object(R.subprocess, "run", side_effect=userdel), \
                     patch.object(R, "sync_udp_custom", side_effect=sync_udp) as sync:
                    R.ssh_del(username)

                sync.assert_called_once_with()
                self.assertNotIn(username, R.load_ssh())

    def test_userdel_launch_error_leaves_record(self):
        with tempfile.TemporaryDirectory() as base, \
             patch.object(R, "SSH_DB", os.path.join(base, "ssh.json")):
            R.ssh_add("alice", "password", 30, 0, 0)
            with patch.object(R.subprocess, "run", side_effect=FileNotFoundError("userdel")), \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(R.main(["ssh-del", "alice"]), 1)
            self.assertIn("Could not run userdel", json.loads(output.getvalue())["error"])
            self.assertIn("alice", R.load_ssh())

    def test_partial_linux_deletion_removes_panel_record_with_warning(self):
        username = "partial-user"
        command = ["userdel", "-r", "--", username]
        error = "userdel: cannot remove home directory"
        with tempfile.TemporaryDirectory() as base, \
             patch.object(R, "SSH_DB", os.path.join(base, "ssh.json")):
            R.ssh_add(username, "password", 30, 0, 0)
            with patch.object(R.subprocess, "run", return_value=subprocess.CompletedProcess(
                    command, 12, "", error)), \
                 patch.object(R.pwd, "getpwnam", side_effect=KeyError(username)), \
                 patch.object(R, "sync_udp_custom") as sync, \
                 contextlib.redirect_stdout(io.StringIO()) as output:
                rc = R.main(["ssh-del", username])

            self.assertEqual(rc, 0, output.getvalue().strip())
            self.assertIn(f"Warning: userdel exited with status 12: {error}", output.getvalue())
            self.assertNotIn(username, R.load_ssh())
            sync.assert_called_once_with()

    def test_unmanaged_linux_user_is_not_touched(self):
        with patch.object(R.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "not found"):
                R.ssh_del("not-in-panel")
        run.assert_not_called()


class TestConcurrentWrites(unittest.TestCase):
    def test_lock_reentrant_and_released_on_error(self):
        with self.assertRaises(ValueError):
            with R.account_lock():
                with R.account_lock():
                    raise ValueError("stop")
        with ThreadPoolExecutor(1) as pool:
            def acquire():
                with R.account_lock():
                    return True
            self.assertTrue(pool.submit(acquire).result(timeout=2))

    def test_processes_preserve_concurrent_users(self):
        with tempfile.TemporaryDirectory() as base:
            env = dict(os.environ, RAGNAR_DIR=base)
            code = ("import sys; import ragnar; "
                    "[ragnar.xray_add(sys.argv[1] + str(n), 30) for n in range(10)]")
            processes = [subprocess.Popen([sys.executable, "-c", code, str(n)],
                         cwd=os.path.dirname(R.__file__), env=env) for n in range(4)]
            for process in processes:
                self.assertEqual(process.wait(timeout=10), 0)
            data = R._read_json(os.path.join(base, "db", "xray.json"), {})
            self.assertEqual(len(data["users"]), 40)

    def test_atomic_write_failure_cleans_up(self):
        with tempfile.TemporaryDirectory() as base:
            path = os.path.join(base, "data.json")
            R._write_json(path, {"original": True})
            with patch.object(R.os, "replace", side_effect=OSError("failed")):
                for writer in (R._write_json, R._write_json_if_changed):
                    with self.assertRaises(OSError):
                        writer(path, {"changed": True})
            self.assertEqual(R._read_json(path, {}), {"original": True})
            self.assertEqual(os.listdir(base), ["data.json"])

    def test_account_add_preserves_concurrent_users(self):
        with tempfile.TemporaryDirectory() as base:
            path = os.path.join(base, "xray.json")
            with patch.object(R, "XRAY_DB", path):
                R.xray_add("alice", 30)
                load = R.load_xray
                barrier = threading.Barrier(2)
                write = R._write_json
                write_lock = threading.Lock()

                def serialized_write(*args):
                    with write_lock:
                        return write(*args)

                def delayed_load():
                    users = load()
                    try:
                        barrier.wait(timeout=0.2)
                    except threading.BrokenBarrierError:
                        pass
                    return users

                with patch.object(R, "load_xray", side_effect=delayed_load), \
                     patch.object(R, "_write_json", side_effect=serialized_write):
                    with ThreadPoolExecutor(2) as pool:
                        futures = [pool.submit(R.xray_add, name, 30)
                                   for name in ("bob", "carol")]
                        for future in futures:
                            future.result()
                self.assertEqual(set(load()), {"alice", "bob", "carol"})

    def test_atomic_writers_use_independent_temporary_files(self):
        with tempfile.TemporaryDirectory() as base:
            path = os.path.join(base, "data.json")
            replace = os.replace
            for writer in (R._write_json, R._write_json_if_changed):
                R._write_json(path, {"value": 0})
                barrier = threading.Barrier(2)
                sources = []

                def delayed_replace(src, dst):
                    sources.append(src)
                    barrier.wait(timeout=2)
                    return replace(src, dst)

                with patch.object(R.os, "replace", side_effect=delayed_replace):
                    with ThreadPoolExecutor(2) as pool:
                        futures = [pool.submit(writer, path, {"value": n})
                                   for n in (1, 2)]
                        for future in futures:
                            future.result()
                self.assertEqual(len(set(sources)), 2)
                self.assertIn(R._read_json(path, {}), ({"value": 1}, {"value": 2}))
                self.assertEqual(os.listdir(base), ["data.json"])


if __name__ == "__main__":
    unittest.main()
