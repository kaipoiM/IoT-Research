#!/usr/bin/env bash
# =============================================================================
# ble_scan.sh — BLE Device Discovery & Pairing Security Analysis
# IoT Security Research | RF Testing | Flipper Zero + Kali
# =============================================================================
# Tests BLE security on smart locks and other BLE IoT devices.
# Covers: device discovery, pairing mode detection, range testing, packet sniffing.
#
# Usage:
#   sudo bash ble_scan.sh --target-mac AA:BB:CC:DD:EE:FF \
#                         --out experiments/smart-lock/logs/ --label lock-s1
#
# Requires: bluetoothctl, hcitool, btmon, gatttool (bluez-utils), tshark
# Flipper Zero with ESP32 module for extended range tests
# =============================================================================

set -euo pipefail

TARGET_MAC=""
OUT_DIR="./output"
LABEL="device"
SCAN_DURATION=60    # seconds for passive BLE scan
RANGE_TEST=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-mac) TARGET_MAC="$2"; shift 2 ;;
    --out)        OUT_DIR="$2";    shift 2 ;;
    --label)      LABEL="$2";      shift 2 ;;
    --duration)   SCAN_DURATION="$2"; shift 2 ;;
    --range-test) RANGE_TEST=true; shift ;;
    *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
  esac
done

mkdir -p "$OUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUT_DIR/ble_${LABEL}_${TIMESTAMP}.log"
RESULTS_FILE="$OUT_DIR/ble_${LABEL}_${TIMESTAMP}.json"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }

log "===== BLE Security Assessment ====="
log "Target MAC : ${TARGET_MAC:-'(discover all)'}"
log "Duration   : ${SCAN_DURATION}s"
log ""

# ── Step 1: Reset HCI adapter ─────────────────────────────────────────────────
log "── Step 1: HCI Adapter Setup ──"
hciconfig hci0 down 2>/dev/null || true
hciconfig hci0 up
hciconfig hci0 | tee -a "$LOG_FILE"

# ── Step 2: Passive BLE device discovery ─────────────────────────────────────
log ""
log "── Step 2: Passive BLE Scan (${SCAN_DURATION}s) ──"
SCAN_OUT="$OUT_DIR/ble_scan_${TIMESTAMP}.txt"

# Enable LE scan (passive)
hcitool lescan --passive --duplicates 2>/dev/null &
SCAN_PID=$!
sleep "$SCAN_DURATION"
kill "$SCAN_PID" 2>/dev/null || true

# Collect with btmon for detailed ADV packets
log "Starting btmon for advertisement packet capture ..."
BTMON_OUT="$OUT_DIR/btmon_${TIMESTAMP}.log"
btmon --write "$BTMON_OUT" &
BTMON_PID=$!

hcitool lescan --duplicates 2>/dev/null &
LE_PID=$!
sleep "$SCAN_DURATION"
kill "$LE_PID" "$BTMON_PID" 2>/dev/null || true

log "Scan complete. btmon log: $BTMON_OUT"

# ── Step 3: Target device GATT service enumeration ───────────────────────────
if [[ -n "$TARGET_MAC" ]]; then
  log ""
  log "── Step 3: GATT Service Enumeration — $TARGET_MAC ──"
  GATT_OUT="$OUT_DIR/gatt_${LABEL}_${TIMESTAMP}.txt"

  # Primary services
  log "Enumerating GATT primary services ..."
  timeout 30 gatttool -b "$TARGET_MAC" --primary 2>&1 | tee "$GATT_OUT" | tee -a "$LOG_FILE" || true

  # Characteristics
  log "Enumerating GATT characteristics ..."
  timeout 30 gatttool -b "$TARGET_MAC" --characteristics 2>&1 | tee -a "$GATT_OUT" | tee -a "$LOG_FILE" || true

  # Check for Generic Access Profile — reveals device name, appearance
  log "Reading Generic Access Profile ..."
  timeout 10 gatttool -b "$TARGET_MAC" -I <<'GATT_EOF' 2>&1 | tee -a "$GATT_OUT" || true
connect
char-read-uuid 00002a00-0000-1000-8000-00805f9b34fb
char-read-uuid 00002a04-0000-1000-8000-00805f9b34fb
disconnect
quit
GATT_EOF

  log "GATT enumeration saved: $GATT_OUT"

  # ── Step 4: Pairing security analysis ─────────────────────────────────────
  log ""
  log "── Step 4: Pairing Security Analysis ──"
  PAIR_OUT="$OUT_DIR/pairing_${LABEL}_${TIMESTAMP}.txt"

  log "Attempting 'Just Works' pairing (no authentication) ..."
  BTMON_PAIR="$OUT_DIR/btmon_pair_${TIMESTAMP}.log"
  btmon --write "$BTMON_PAIR" &
  BTMON_PAIR_PID=$!

  # Try pairing without PIN — "Just Works" mode
  timeout 20 bluetoothctl <<BTEOF 2>&1 | tee "$PAIR_OUT" | tee -a "$LOG_FILE" || true
power on
agent NoInputNoOutput
default-agent
scan on
pair $TARGET_MAC
info $TARGET_MAC
scan off
BTEOF

  kill "$BTMON_PAIR_PID" 2>/dev/null || true

  # Analyze pairing result
  if grep -qi "paired: yes\|Paired: yes" "$PAIR_OUT" 2>/dev/null; then
    log "⚠  FINDING: Device paired using 'Just Works' (no authentication)" "WARN"
    echo '{"finding": "BLE_JUST_WORKS_PAIRING", "severity": "HIGH"}' >> "$RESULTS_FILE"
    log "   OWASP: I1 (Weak Authentication) | BLE 4.x without ECDH key exchange"
    log "   Relevant CVEs: devices using BLE < 4.2 lack ECDH LTK protection"
  elif grep -qi "Failed\|refused" "$PAIR_OUT" 2>/dev/null; then
    log "✓  Device rejected unauthenticated pairing — secure pairing required"
  else
    log "  Pairing result inconclusive — check $PAIR_OUT"
  fi

  # ── Step 5: BLE packet sniffing ────────────────────────────────────────────
  log ""
  log "── Step 5: BLE Packet Sniffing ──"
  BLE_PCAP="$OUT_DIR/ble_${LABEL}_${TIMESTAMP}.pcap"

  # Convert btmon log to pcap format if possible
  if command -v btmon &>/dev/null && [[ -f "$BTMON_OUT" ]]; then
    log "Converting btmon log to pcap ..."
    btmon --read "$BTMON_OUT" --btsnoop "$BLE_PCAP" 2>/dev/null || true
    if [[ -f "$BLE_PCAP" ]]; then
      log "BLE pcap created: $BLE_PCAP"
      log "Analyze with: tshark -r $BLE_PCAP -Y btle"
    fi
  fi

  # Check encryption status in BLE advertisements
  log ""
  log "Checking BLE encryption in captured traffic ..."
  if command -v tshark &>/dev/null && [[ -f "$BLE_PCAP" ]]; then
    ENCRYPT_COUNT=$(tshark -r "$BLE_PCAP" -Y "btle.data_header.llid == 2" 2>/dev/null | wc -l || echo 0)
    UNENCRYPT_COUNT=$(tshark -r "$BLE_PCAP" -Y "btle.advertising_header" 2>/dev/null | wc -l || echo 0)
    log "BLE data packets    : $ENCRYPT_COUNT"
    log "BLE advertisement   : $UNENCRYPT_COUNT"
  fi
fi

# ── Step 6: Range test (with Flipper Zero ESP32) ──────────────────────────────
if [[ "$RANGE_TEST" == "true" ]]; then
  log ""
  log "── Step 6: BLE Range Extension Test ──"
  log "NOTE: This test requires Flipper Zero with ESP32 module."
  log ""
  log "Manual procedure:"
  log "  1. Use Flipper Zero > Bluetooth > BLE Spam / Scanner at standard 10m range"
  log "  2. Gradually increase distance, recording last successful connection"
  log "  3. Attach directional antenna to ESP32, repeat"
  log "  4. Document maximum connection range with and without directional antenna"
  log ""
  log "Expected finding per research: BLE range can be extended to 400m+"
  log "  with directional antenna (Lounis & Zulkernine, 2019)"
  log ""
  log "Record results:"
  RANGE_LOG="$OUT_DIR/range_test_${LABEL}_${TIMESTAMP}.txt"
  cat > "$RANGE_LOG" <<RANGEEOF
BLE Range Extension Test — $LABEL
Date: $(date)
Target MAC: $TARGET_MAC

[ ] Standard range (BLE default ~10m): _____ m
[ ] With Flipper Zero + standard antenna: _____ m
[ ] With Flipper Zero + directional antenna: _____ m
[ ] Maximum observed range before disconnect: _____ m

Notes:
RANGEEOF
  log "Range test template: $RANGE_LOG"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
log ""
log "===== BLE Assessment Complete ====="
log "Evidence files:"
ls -lh "$OUT_DIR/"*"$TIMESTAMP"* 2>/dev/null | tee -a "$LOG_FILE" || true
log ""
log "Next steps:"
log "  - Review GATT services for sensitive characteristics (auth tokens, PINs)"
log "  - Check btmon log for key exchange method: LE Legacy vs LE Secure Connections"
log "  - Run: tshark -r $OUT_DIR/ble_*.pcap -Y btle -T fields -e btle.advertising_address"
log "  - Test reconnection auth: unpair, then replay captured handshake"
