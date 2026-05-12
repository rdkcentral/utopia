#!/bin/sh
# Firewall fix for device 40:75:C3:3B:7D:44
# Root cause: CS4 marking is not present on the WiFi interface (wl0) — the WiFi driver or WMM layer is likely stripping/downgrading DSCP before packets enter the bridge, so CS4 never reaches the WAN
# Generated: 2026-05-12 19:56:06 UTC
# Job ID: 76a3d3d2-2e2

Verify the client is actually sending CS4-marked packets (capture at the client itself)
Check WiFi driver WMM/DSCP mapping — many Memory WiFi drivers remap DSCP on ingress; look for 'wmm_dscp' or 'dscp_prio_map' parameters
Inspect mangle POSTROUTING and prerouting_qos for any --set-dscp or DSCP 0x00 rules
Validate with: tcpdump -i erouter0 -v 'ip[1] & 0xfc == 0x80' -c 10
