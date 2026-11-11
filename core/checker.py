#!/usr/bin/env python3
"""
Ragnar limit checker - run every minute by ragnar-check.timer.

Enforces, for every panel user:
  * expiry date          (SSH: lock account + kill sessions; Xray: disable + regen)
  * GB quota             (same actions; counters below)
  * SSH IP limit         (extra source IPs get their sessions killed)

Traffic counters:
  * Xray: `xray api statsquery` user>>>email>>>traffic counters are added
    into used_bytes (Xray resets its counters on restart, so we accumulate
    deltas into the panel DB each run).
  * SSH: iptables owner-match chains (RAGNAR_IN_<user> / RAGNAR_OUT_<user>)
    created by the installer; byte counters are read with `iptables -nvxL`
    and accumulated the same way.

Without --apply it only prints the plan (dry run).
"""
import json
import os
import pwd
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ragnar  # noqa: E402


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def xray_deltas():
    """{email: bytes} since last run, from the Xray Stats API."""
    out = run("/usr/local/bin/xray api statsquery -server=127.0.0.1:10085 2>/dev/null")
    deltas = {}
    try:
        data = json.loads(out) if out.strip() else {}
    except ValueError:
        return deltas
    for stat in data.get("stat", []):
        # name: user>>>email>>>traffic>>>uplink|downlink
        parts = stat.get("name", "").split(">>>")
        if len(parts) == 4 and parts[0] == "user":
            email = parts[1]
            deltas[email] = deltas.get(email, 0) + int(stat.get("value", 0))
    return deltas


def ssh_live_ips():
    """{(kind, user): [ip,...]} from live sshd/dropbear sockets via /proc."""
    live = {}
    out = run("ss -tnp state established 2>/dev/null")
    for line in out.splitlines():
        m = re.search(r'users:\(\("(\w+)",pid=(\d+),fd=\d+\)\)', line)
        ip = re.search(r"\[?(\d+\.\d+\.\d+\.\d+)\]?:\d+\s*$", line.strip())
        if not m or not ip:
            continue
        prog, pid = m.group(1), int(m.group(2))
        if prog not in ("sshd", "dropbear"):
            continue
        try:
            with open(f"/proc/{pid}/status") as fh:
                uid = int(re.search(r"^Uid:\s+(\d+)", fh.read(), re.M).group(1))
            user = pwd.getpwuid(uid).pw_name
        except Exception:
            continue
        live.setdefault(("ssh", user), []).append(ip.group(1))
    return live


def ensure_iptables_rules(ssh):
    """One counting rule per SSH user in OUTPUT (owner match).

    Traffic an SSH user forwards leaves the box from a process running
    as that user, so owner-match byte counters attribute it correctly.
    """
    existing = run("iptables -S OUTPUT 2>/dev/null")
    for user in ssh:
        try:
            uid = pwd.getpwnam(user).pw_uid
        except KeyError:
            continue
        if f"--uid-owner {uid}" not in existing:
            run(f"iptables -A OUTPUT -m owner --uid-owner {uid} -j RETURN")


def accumulate_usage():
    ssh = ragnar.load_ssh()
    ensure_iptables_rules(ssh)
    changed = False
    # iptables per-user counters
    counters = run("iptables -nvxL OUTPUT 2>/dev/null")
    per_user = {}
    for line in counters.splitlines():
        m = re.match(r"\s*\d+\s+(\d+)\s+.*owner UID match (\d+)", line)
        if m:
            try:
                user = pwd.getpwuid(int(m.group(2))).pw_name
            except KeyError:
                continue
            per_user[user] = per_user.get(user, 0) + int(m.group(1))
    state_f = os.path.join(ragnar.BASE, "db", "ssh_counter_state.json")
    prev = ragnar._read_json(state_f, {})
    for user, total in per_user.items():
        if user in ssh:
            delta = max(0, total - int(prev.get(user, 0)))
            if delta:
                ssh[user]["used_bytes"] = int(ssh[user].get("used_bytes", 0)) + delta
                changed = True
    if per_user:
        ragnar._write_json(state_f, per_user)
    if changed:
        ragnar.save_ssh(ssh)

    xr = ragnar.load_xray()
    deltas = xray_deltas()
    state_f = os.path.join(ragnar.BASE, "db", "xray_counter_state.json")
    prev = ragnar._read_json(state_f, {})
    changed = False
    for email, total in deltas.items():
        if email in xr:
            delta = max(0, total - int(prev.get(email, 0)))
            if delta:
                xr[email]["used_bytes"] = int(xr[email].get("used_bytes", 0)) + delta
                changed = True
    if deltas:
        ragnar._write_json(state_f, deltas)
    if changed:
        ragnar.save_xray(xr)
    return ssh, xr


def main():
    apply_mode = "--apply" in sys.argv
    ssh, xr = accumulate_usage()
    live = ssh_live_ips()
    plan = ragnar.enforcement_plan(ssh, xr, live)
    for item in plan:
        print(f"{item['kind']}/{item['user']}: {item['action']} ({item['reason']})")
        if not apply_mode:
            continue
        if item["kind"] == "ssh" and item["action"] == "lock":
            run(f"usermod -L {item['user']}; pkill -u {item['user']} 2>/dev/null; true")
            u = ssh[item["user"]]; u["enabled"] = False; ragnar.save_ssh(ssh)
        elif item["kind"] == "ssh" and item["action"] == "kick-extra":
            ips = list(dict.fromkeys(live.get(("ssh", item["user"]), [])))
            keep = set(ips[: int(ssh[item["user"]].get("ip_limit", 0))])
            for line in run("ss -tnp state established 2>/dev/null").splitlines():
                m = re.search(r"\[?(\d+\.\d+\.\d+\.\d+)\]?:\d+\s+.*pid=(\d+)", line)
                if m and m.group(1) not in keep:
                    run(f"kill {m.group(2)} 2>/dev/null; true")
        elif item["kind"] == "xray" and item["action"] == "remove":
            u = xr[item["user"]]; u["enabled"] = False; ragnar.save_xray(xr)
            ragnar.apply_configs()
    if not plan:
        print("all users within limits")
    return 0


if __name__ == "__main__":
    sys.exit(main())
