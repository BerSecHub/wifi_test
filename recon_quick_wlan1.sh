#!/usr/bin/env bash
# recon_quick_wlan1.sh — 45s channel-hop survey & optional target capture
# Usage:
#   sudo ./recon_quick_wlan1.sh [TARGET_CH] [AP_BSSID]
# If TARGET_CH and AP_BSSID given, performs an extra targeted airodump
set -Eeuo pipefail
IFACE="${IFACE:-wlan1}"
TCH="${1:-}"
TBSSID="${2:-}"

PCAP_DIR="${HOME}/wifi/pcap"
mkdir -p "$PCAP_DIR"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[!] Missing: $1"; MISSING=1; }; }
MISSING=0
for c in iw ip airmon-ng airodump-ng; do need "$c"; done
if (( MISSING )); then
  echo "[!] Install: sudo apt install aircrack-ng"
  exit 1
fi
ts(){ date +%F_%H%M%S; }

echo "[*] Kill NM/wpa_supplicant"; sudo airmon-ng check kill || true
echo "[*] Monitor mode on ${IFACE}"; sudo ip link set "$IFACE" down; sudo iw dev "$IFACE" set type monitor; sudo ip link set "$IFACE" up

SUR="${PCAP_DIR}/survey_$(ts)"
echo "[*] 45s survey -> ${SUR}-*.cap (airodump-ng)"
sudo timeout 45s airodump-ng --write-interval 1 -w "$SUR" "$IFACE" || true

if [[ -n "$TCH" && -n "$TBSSID" ]]; then
  echo "[*] Target capture on CH $TCH BSSID $TBSSID"
  sudo iw dev "$IFACE" set channel "$TCH"
  sudo timeout 60s airodump-ng -c "$TCH" --bssid "$TBSSID" -w "${PCAP_DIR}/target_$(ts)" "$IFACE" || true
fi

echo "[i] To restore networking: sudo ./wifi_teardown.sh ${IFACE}"
