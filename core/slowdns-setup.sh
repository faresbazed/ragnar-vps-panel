#!/usr/bin/env bash
# REPLACED on 2026-11-13 at the user's explicit request ("all code
# replaced"): SlowDNS in this panel is now the implementation from
# faresbazed/Ragnar-VPS-Management-Panel, byte-for-byte, in
# core/ragnar-slowdns-setup (installed as /usr/local/bin/ragnar-slowdns-setup,
# config in /etc/vps-panel/slowdns/). This file remains only so that
# anything still pointing at the old port fails loudly instead of
# silently running superseded code.
echo "slowdns-setup.sh has been replaced by ragnar-slowdns-setup (see core/ragnar-slowdns-setup)" >&2
exit 1
