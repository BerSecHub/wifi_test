# Ready-made Wi‑Fi testing tools & helper scripts

## Install the useful bundles
```bash
sudo apt update
sudo apt -y install kali-linux-wireless aircrack-ng kismet hcxdumptool hcxtools hashcat \
  eaphammer hostapd-wpe wifite airgeddon bettercap mdk4 tshark
```

## What each tool is for
- **wifite** — autopilot for handshake/PMKID & basic attacks (PSK).
- **airgeddon** — interactive TUI combining aircrack/hcxtools/hashcat/Wifiphisher.
- **eaphammer** — automated rogue 802.1X (PEAP/MSCHAPv2) with credential capture.
- **hostapd‑wpe** — manual rogue 802.1X with full control.
- **kismet** — passive recon/WIDS logging.
- **hcxdumptool/hcxtools** — PMKID/4‑way capture & convert to 22000.
- **hashcat** — offline cracking (mode 22000 + rules).
- **aircrack‑ng** — airodump/aireplay classics (scan/handshake/deauth).
- **mdk4** — stress/deauth/beacon/etc. (scope only!)
- **bettercap** — full‑stack sniffer/MITM with 802.11/BLE modules.

## Included helper scripts (default iface: wlan1)
- `recon_quick_wlan1.sh` — 45s survey + optional targeted capture
- `psk_quick_wlan1.sh` — PMKID/4‑way capture & hashcat
- `enterprise_quick_wlan1.sh` — Rogue 802.1X launcher (EAPHammer/hostapd‑wpe)
- `wifi_teardown.sh` — restore networking (managed mode)
- See also previously shared: `wifi_prep_wlan1.sh` (prep + smoke tests)

## Minimal flow (cheat)
```bash
# Recon
sudo ./recon_quick_wlan1.sh

# PSK path
sudo ./psk_quick_wlan1.sh <CH> 180 /usr/share/wordlists/rockyou.txt

# Enterprise path (authorized window only)
sudo ./enterprise_quick_wlan1.sh <CH> "<CORP_SSID>"

# Pack & restore
tar czvf ~/wifi_artifacts_$(date +%F_%H%M).tgz ~/wifi
sudo ./wifi_teardown.sh wlan1
```

> Run tests only with written authorization. Respect local RF/EIRP limits.
