#!/usr/bin/env bash
# =============================================================================
# zigbee_sniff.sh — Zigbee Traffic Capture & Key Exposure Analysis
# IoT Security Research | RF Testing | HackRF One + GNU Radio / Wireshark
# =============================================================================
# Captures Zigbee (802.15.4) traffic at 2.4 GHz to assess encryption status,
# default/well-known network key usage, and commissioning vulnerabilities
# per Ghobakhlou et al. (2025) Zigbee 3.0 security analysis [19].
#
# Covers: channel identification, traffic capture, encryption verification,
# network key exposure check during commissioning/pairing.
#
# Usage:
#   sudo bash zigbee_sniff.sh --channel 15 --label sensor-s1 \
#                              --out experiments/smart-lock/logs/ --duration 300
#
# Requires: HackRF One, gr-ieee802-15-4 (GNU Radio OOT module) OR
#           Wireshark with an nRF52840 dongle/sniffer firmware as alternative,
#           Killerbee framework (optional, for key extraction assistance)
#
# NOTE: Zigbee channels 11-26 map to 2.405-2.480 GHz in 5 MHz steps:
#       freq_MHz = 2405 + 5 * (channel - 11)
# =============================================================================

set -euo pipefail

CHANNEL=15
OUT_DIR="./output"
LABEL="device"
DURATION=300   # seconds
STATE=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --channel)  CHANNEL="$2";  shift 2 ;;
    --out)      OUT_DIR="$2";  shift 2 ;;
    --label)    LABEL="$2";    shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --state)    STATE="$2";    shift 2 ;;
    *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
  esac
done

mkdir -p "$OUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUT_DIR/zigbee_${LABEL}_${TIMESTAMP}.log"
RESULTS_FILE="$OUT_DIR/zigbee_${LABEL}_${TIMESTAMP}.json"
PCAP_FILE="$OUT_DIR/zigbee_${LABEL}_${TIMESTAMP}.pcap"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }

FREQ_MHZ=$(python3 -c "print(2405 + 5 * (${CHANNEL} - 11))")

log "===== Zigbee Traffic Assessment ====="
log "Channel          : ${CHANNEL} (${FREQ_MHZ} MHz)"
log "Device label     : ${LABEL}"
log "Config state     : State ${STATE}"
log "Capture duration : ${DURATION}s"
log ""

# ── Step 1: HackRF sanity check ───────────────────────────────────────────────
log "── Step 1: HackRF Device Check ──"
if command -v hackrf_info &>/dev/null; then
  hackrf_info 2>&1 | tee -a "$LOG_FILE" || log "⚠  HackRF not detected — check USB connection"
else
  log "⚠  hackrf_info not found — install hackrf tools (apt install hackrf)"
fi
log ""

# ── Step 2: Channel scan to confirm device activity ───────────────────────────
log "── Step 2: Channel Activity Confirmation ──"
log "If exact channel unknown, scan all Zigbee channels (11-26) for activity:"
log "  for ch in {11..26}; do"
log "    freq=\$((2405 + 5 * (ch - 11)))"
log "    echo \"Channel \$ch: \${freq} MHz\""
log "    hackrf_transfer -r /tmp/scan_ch\${ch}.raw -f \${freq}000000 -s 4000000 -n 4000000"
log "  done"
log "Trigger device activity (pairing, state change) while scanning to identify its channel."
log ""

# ── Step 3: Capture Zigbee traffic via GNU Radio / gr-ieee802-15-4 ───────────
log "── Step 3: Zigbee Capture (Channel ${CHANNEL} / ${FREQ_MHZ} MHz) ──"
log "Using gr-ieee802-15-4 companion flowgraph (ieee802_15_4_capture.grc):"
log "  1. Set HackRF center frequency: ${FREQ_MHZ} MHz"
log "  2. Sample rate: 4 MHz (minimum for O-QPSK demod at 2 Mchip/s)"
log "  3. Output: PCAP via 'Wireshark Connector' block on UDP loopback, or direct pcap sink"
log ""
log "Alternative (recommended if gr-ieee802-15-4 unavailable):"
log "  Use an nRF52840 dongle flashed with Wireshark sniffer firmware for direct"
log "  channel ${CHANNEL} capture into Wireshark, since HackRF+GNU Radio demod"
log "  chains for O-QPSK are comparatively unreliable for reliable frame capture."
log ""
read -rp "  Press Enter once capture is running, then trigger device activity..." _
log "Capturing for ${DURATION}s — trigger device pairing/state changes now."
sleep 1
log "(Manually stop capture and export as: $PCAP_FILE)"
read -rp "  Press Enter once capture is saved to $PCAP_FILE..." _

if [[ -f "$PCAP_FILE" ]]; then
  PACKET_COUNT=$(command -v tshark &>/dev/null && tshark -r "$PCAP_FILE" 2>/dev/null | wc -l || echo "unknown")
  log "Capture saved: $PCAP_FILE ($PACKET_COUNT packets)"
else
  log "⚠  No pcap file found at expected path — verify export location"
  PACKET_COUNT=0
fi

# ── Step 4: Encryption status analysis ────────────────────────────────────────
log ""
log "── Step 4: Encryption Status Analysis ──"
if command -v tshark &>/dev/null && [[ -f "$PCAP_FILE" ]]; then
  log "Checking Auxiliary Security Header presence (indicates APS/NWK encryption)..."
  SECURED=$(tshark -r "$PCAP_FILE" -Y "zbee_nwk.security" 2>/dev/null | wc -l || echo 0)
  UNSECURED=$(tshark -r "$PCAP_FILE" -Y "zbee_nwk && not zbee_nwk.security" 2>/dev/null | wc -l || echo 0)
  log "  Secured NWK frames   : $SECURED"
  log "  Unsecured NWK frames : $UNSECURED"
else
  log "tshark unavailable or no pcap — record manually via Wireshark Zigbee dissector"
  read -rp "  Secured frames observed (y/n): " SECURED_MANUAL
  SECURED=$([[ "$SECURED_MANUAL" =~ ^[Yy]$ ]] && echo 1 || echo 0)
  UNSECURED=$([[ "$SECURED_MANUAL" =~ ^[Yy]$ ]] && echo 0 || echo 1)
fi

if (( UNSECURED > 0 )); then
  ENCRYPTION_FINDING="UNENCRYPTED_TRAFFIC"
  log "⚠  FINDING: Unencrypted Zigbee NWK frames detected"
else
  ENCRYPTION_FINDING="ENCRYPTED"
  log "✓  All observed NWK frames use security header (encrypted)"
fi

# ── Step 5: Commissioning / key exposure check ────────────────────────────────
log ""
log "── Step 5: Network Key Exposure During Commissioning ──"
log "Zigbee's most critical exposure window is initial commissioning, when the"
log "network key may be transmitted using the well-known default Trust Center"
log "link key (Zigbee 3.0 default: 5A6967426565416C6C69616E63653039)."
log ""
log "Procedure:"
log "  1. Factory reset the device (forces re-commissioning)"
log "  2. Capture the full join sequence on channel ${CHANNEL}"
log "  3. In Wireshark, set the well-known Trust Center link key under:"
log "     Edit > Preferences > Protocols > ZigBee > pre-configured keys"
log "  4. Attempt to decrypt the Transport Key command using this key"
read -rp "  Did the well-known default TC link key successfully decrypt traffic? (y/n): " DEFAULT_KEY
if [[ "$DEFAULT_KEY" =~ ^[Yy]$ ]]; then
  KEY_FINDING="DEFAULT_KEY_SUCCESSFUL"
  log "⚠  FINDING: Default/well-known Trust Center link key decrypts commissioning traffic"
  log "   OWASP: I1 (Weak/Guessable Credentials) | Ref: Ghobakhlou et al. 2025 [19]"
else
  KEY_FINDING="CUSTOM_KEY_OR_NOT_TESTED"
  log "✓  Default key did not decrypt traffic — custom key or install-code in use"
fi

# ── Results JSON ──────────────────────────────────────────────────────────────
cat > "$RESULTS_FILE" <<JSONEOF
{
  "test_id": "ZIGBEE-${LABEL}-${TIMESTAMP}",
  "timestamp": "$(date -Iseconds)",
  "device_label": "${LABEL}",
  "configuration_state": ${STATE},
  "channel": ${CHANNEL},
  "frequency_mhz": ${FREQ_MHZ},
  "capture_file": "${PCAP_FILE}",
  "packet_count": "${PACKET_COUNT}",
  "secured_frames": ${SECURED},
  "unsecured_frames": ${UNSECURED},
  "encryption_status": "${ENCRYPTION_FINDING}",
  "commissioning_key_finding": "${KEY_FINDING}",
  "owasp_category": "I1",
  "etsi_provision": "5.5",
  "findings": [
$( [[ "$ENCRYPTION_FINDING" == "UNENCRYPTED_TRAFFIC" ]] && echo '    {"severity": "CRITICAL", "issue": "Unencrypted Zigbee NWK traffic observed", "owasp": "I7", "etsi": "5.5"},' )
$( [[ "$KEY_FINDING" == "DEFAULT_KEY_SUCCESSFUL" ]] && echo '    {"severity": "CRITICAL", "issue": "Well-known default Trust Center link key decrypts commissioning", "owasp": "I1", "etsi": "5.1", "reference": "Ghobakhlou et al. 2025"},' )
    {"severity": "INFO", "issue": "Test complete", "owasp": "N/A", "etsi": "N/A"}
  ]
}
JSONEOF

log ""
log "===== Zigbee Assessment Complete ====="
log "Results saved : $RESULTS_FILE"
log "Capture file  : $PCAP_FILE"
log ""
log "Next steps:"
log "  - If default key succeeded, verify against Zigbee 3.0 install-code requirement"
log "  - Cross-reference findings with score_device.py for three-state comparison"
log "  - If novel/undocumented vulnerability found, use templates/vuln-report.md"
