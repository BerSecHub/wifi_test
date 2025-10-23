#!/usr/bin/env bash
# wifi_teardown.sh — restore managed mode and networking
# Usage: sudo ./wifi_teardown.sh [iface]   # default iface=wlan1
set -Eeuo pipefail
IFACE="${1:-wlan1}"
echo "[*] Restoring managed mode on ${IFACE} and restarting NetworkManager…"
sudo ip link set "$IFACE" down || true
sudo iw dev "$IFACE" set type managed || true
sudo ip link set "$IFACE" up || true
sudo systemctl restart NetworkManager || true
echo "[*] Current interface info:"
iw dev "$IFACE" info || true
