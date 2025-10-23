#!/usr/bin/env bash
# wifi_prep_wlan1.sh — prep + smoke tests for Wi‑Fi pentest rig (wlan1)
# Usage:
#   sudo ./wifi_prep_wlan1.sh [iface]         # default iface=wlan1
#   CH=11 sudo ./wifi_prep_wlan1.sh           # optional: fix channel via CH env var
# Notes:
# - Run with authorization only. Comply with local RF laws/limits.
# - This script kills NetworkManager/wpa_supplicant temporarily.
set -Eeuo pipefail

IFACE="${1:-wlan1}"
CH="${CH:-}"

PCAP_DIR="${HOME}/wifi/pcap"
LOG_DIR="${HOME}/wifi/logs"
HASH_DIR="${HOME}/wifi/hashes"
mkdir -p "$PCAP_DIR" "$LOG_DIR" "$HASH_DIR"

ts(){ date +%F_%H%M%S; }

need() { command -v "$1" >/dev/null 2>&1 || { echo "[!] Missing: $1"; MISSING=1; }; }
MISSING=0
for c in iw ip airmon-ng tcpdump aireplay-ng airodump-ng; do need "$c"; done
if (( MISSING )); then
  echo "[!] Install missing tools, e.g.: sudo apt install aircrack-ng tcpdump"
  exit 1
fi

echo "[*] Regulatory domain -> PL"
sudo iw reg set PL || true

echo "[*] Interface info BEFORE:"
iw dev "$IFACE" info || true
ethtool -i "$IFACE" 2>/dev/null || true

echo "[*] Killing interfering services (NetworkManager/wpa_supplicant)…"
sudo airmon-ng check kill || true

echo "[*] Switching $IFACE to monitor mode"
sudo ip link set "$IFACE" down || true
sudo iw dev "$IFACE" set type monitor
sudo ip link set "$IFACE" up

if [[ -n "$CH" ]]; then
  echo "[*] Setting channel: $CH"
  sudo iw dev "$IFACE" set channel "$CH"
fi

SMOKE="$PCAP_DIR/smoke_$(ts).pcap"
echo "[*] Quick smoke capture (200 frames) -> $SMOKE"
sudo timeout 20s tcpdump -I -i "$IFACE" -s 0 -w "$SMOKE" -c 200 || true

INJLOG="$LOG_DIR/injection_test_$(ts).log"
echo "[*] Injection test via aireplay-ng (log -> $INJLOG)"
sudo aireplay-ng -9 "$IFACE" | tee "$INJLOG" || true

SUR_PREFIX="$PCAP_DIR/survey_$(ts)"
echo "[*] 30s channel‑hop survey (airodump-ng) -> ${SUR_PREFIX}-*.cap"
sudo timeout 30s airodump-ng --write-interval 1 -w "$SUR_PREFIX" "$IFACE" || true

echo ""
echo "[✓] Prep completed."
echo "Next:"
echo "  • Target capture (static channel): sudo airodump-ng -c <CH> --bssid <AP_BSSID> -w $PCAP_DIR/target $IFACE"
echo "  • PMKID/4‑way: CH=<CH> sudo iw dev $IFACE set channel <CH>; sudo hcxdumptool -i $IFACE -o $PCAP_DIR/cap.pcapng --enable_status=1"
echo "  • Convert: hcxpcapngtool -o $HASH_DIR/psk.22000 $PCAP_DIR/cap.pcapng"
echo "  • Crack (example): hashcat -m 22000 $HASH_DIR/psk.22000 /usr/share/wordlists/rockyou.txt -O"
echo ""
echo "  • Restore managed mode afterwards: sudo ./wifi_teardown.sh $IFACE"
