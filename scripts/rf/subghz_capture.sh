#!/usr/bin/env bash
# =============================================================================
# subghz_capture.sh — Sub-GHz Signal Capture, Replay & Jamming Assessment
# IoT Security Research | RF Testing | Flipper Zero
# =============================================================================
# Tests Sub-GHz protocol security on smart locks, sensors, and simple
# automation devices operating at 315/433/868/915 MHz.
#
# Covers: frequency identification, signal capture, replay attack,
# rolling-code detection, and jamming/DoS resistance.
#
# NOTE: This script guides manual Flipper Zero operations (Flipper CLI/qFlipper
# do not expose a stable scripting API for RF capture as of this writing).
# It generates structured logs and a JSON result file from operator input.
#
# Usage:
#   bash subghz_capture.sh --freq 433.92 --label lock-s1 \
#                           --out experiments/smart-lock/logs/
#
# Requires: Flipper Zero (Sub-GHz module), Faraday bag/cage for jamming tests
# Reference: inFactory-style ASK/OOK sensors use static unencrypted signaling [22]
# =============================================================================

set -euo pipefail

FREQ="433.92"
OUT_DIR="./output"
LABEL="device"
STATE=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --freq)  FREQ="$2";     shift 2 ;;
    --out)   OUT_DIR="$2";  shift 2 ;;
    --label) LABEL="$2";    shift 2 ;;
    --state) STATE="$2";    shift 2 ;;
    *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
  esac
done

mkdir -p "$OUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUT_DIR/subghz_${LABEL}_${TIMESTAMP}.log"
RESULTS_FILE="$OUT_DIR/subghz_${LABEL}_${TIMESTAMP}.json"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }

log "===== Sub-GHz Signal Assessment ====="
log "Target frequency : ${FREQ} MHz"
log "Device label     : ${LABEL}"
log "Config state     : State ${STATE}"
log ""

# ── Common consumer Sub-GHz frequencies for reference ────────────────────────
log "── Reference: Common Sub-GHz ISM Frequencies ──"
log "  315.00 MHz — US garage doors, TPMS, older remotes"
log "  433.92 MHz — EU/global sensors, doorbells, weather stations, remotes"
log "  868.30 MHz — EU smart home (Z-Wave EU, some sensors)"
log "  915.00 MHz — US Z-Wave, LoRa, some smart locks"
log ""

# ── Step 1: Frequency identification (manual — Flipper Zero Frequency Analyzer) ──
log "── Step 1: Frequency Identification ──"
log "On Flipper Zero: Main Menu > Sub-GHz > Read > Frequency Analyzer"
log "  1. Hold Flipper within 1-2m of device"
log "  2. Trigger device action (press remote, open sensor contact, etc.)"
log "  3. Record the detected frequency and RSSI"
log ""
read -rp "  Confirmed frequency detected (MHz) [default ${FREQ}]: " DETECTED_FREQ
DETECTED_FREQ="${DETECTED_FREQ:-$FREQ}"
log "Confirmed frequency: ${DETECTED_FREQ} MHz"

# ── Step 2: Normal operation capture ─────────────────────────────────────────
log ""
log "── Step 2: Normal Operation Signal Capture ──"
log "On Flipper Zero: Sub-GHz > Read Raw (or Read, if protocol auto-detected)"
log "  1. Set frequency to ${DETECTED_FREQ} MHz, modulation: AM650 (OOK) or FM238 (2FSK)"
log "  2. Trigger device action 3-5 times, save each capture separately"
log "  3. Transfer .sub files from Flipper SD card to this machine"
log ""
CAPTURE_DIR="$OUT_DIR/captures_${LABEL}_${TIMESTAMP}"
mkdir -p "$CAPTURE_DIR"
log "Save/copy .sub files to: $CAPTURE_DIR"
read -rp "  Press Enter once capture files are copied to that directory..." _

CAPTURE_COUNT=$(find "$CAPTURE_DIR" -name "*.sub" 2>/dev/null | wc -l)
log "Capture files found: $CAPTURE_COUNT"

# ── Step 3: Signal analysis — static vs rolling code ─────────────────────────
log ""
log "── Step 3: Static vs. Rolling Code Analysis ──"
log "Compare captured .sub files byte-for-byte (or via Flipper's raw view):"
log "  - IDENTICAL payloads across captures => static code (vulnerable to replay)"
log "  - DIFFERING payloads each time       => rolling/hopping code (replay-resistant)"
log ""
read -rp "  Are captured signals identical across repeated triggers? (y/n): " STATIC_CODE
if [[ "$STATIC_CODE" =~ ^[Yy]$ ]]; then
  ROLLING_CODE="NO"
  log "⚠  FINDING: Static signal detected — no rolling code implementation"
else
  ROLLING_CODE="YES"
  log "✓  Signal varies between captures — rolling code likely implemented"
fi

# ── Step 4: Replay attack ────────────────────────────────────────────────────
log ""
log "── Step 4: Replay Attack Test ──"
log "On Flipper Zero: Sub-GHz > Saved > select capture > Send"
log "  1. Ensure device is in normal listening state"
log "  2. Replay the captured signal"
log "  3. Observe whether the device performs the original action"
log ""
read -rp "  Did replay trigger the device action? (y/n): " REPLAY_SUCCESS
if [[ "$REPLAY_SUCCESS" =~ ^[Yy]$ ]]; then
  REPLAY_RESULT="SUCCESS"
  log "⚠  FINDING: Replay attack SUCCEEDED — device accepted captured signal"
else
  REPLAY_RESULT="FAILURE"
  log "✓  Replay attack FAILED — device rejected replayed signal"
fi

# ── Step 5: Signal variation / brute-force analysis (if static) ──────────────
if [[ "$ROLLING_CODE" == "NO" ]]; then
  log ""
  log "── Step 5: Signal Variation Analysis ──"
  log "Since signal is static, assess brute-force feasibility:"
  log "On Flipper Zero: Sub-GHz > Add Manually > select protocol + bruteforce"
  log "  (De Bruijn sequence attack for fixed-code garage doors/gates, if supported)"
  read -rp "  Estimated keyspace / bit length (if known): " KEYSPACE
  log "Keyspace/bit length noted: ${KEYSPACE:-unknown}"
fi

# ── Step 6: Jamming / DoS test ────────────────────────────────────────────────
log ""
log "── Step 6: RF Jamming / Denial-of-Service Test ──"
log "⚠  SAFETY: Perform this test ONLY inside a Faraday bag/cage."
log "⚠  LEGAL: Confirm containment prevents any signal leakage before proceeding (47 CFR Part 15)."
log ""
read -rp "  Confirm testing is contained in Faraday bag/cage (y/n): " SHIELDED
if [[ ! "$SHIELDED" =~ ^[Yy]$ ]]; then
  log "✗  Jamming test SKIPPED — shielding not confirmed. Do not transmit unshielded."
else
  log "On Flipper Zero: Sub-GHz > Frequency Jammer (or continuous TX at low power)"
  log "  1. Start jamming at ${DETECTED_FREQ} MHz, minimum power needed for effect"
  log "  2. Attempt device action during jamming"
  log "  3. Time how long disruption persists after jamming stops"
  echo ""
  START_JAM=$(date +%s)
  read -rp "  Device disrupted? (y/n): " JAMMED
  read -rp "  Duration of disruption after jam stopped (seconds): " JAM_DURATION
  JAM_DURATION="${JAM_DURATION:-0}"

  if [[ "$JAMMED" =~ ^[Yy]$ ]] && (( JAM_DURATION > 30 )); then
    JAM_RESULT="SUCCESS"
    log "⚠  FINDING: Jamming attack SUCCEEDED — disruption exceeded 30s threshold (${JAM_DURATION}s)"
  elif [[ "$JAMMED" =~ ^[Yy]$ ]]; then
    JAM_RESULT="PARTIAL"
    log "~  Jamming caused disruption but recovered within 30s (${JAM_DURATION}s)"
  else
    JAM_RESULT="FAILURE"
    log "✓  Device resisted jamming attempt"
  fi
fi

# ── Results JSON ──────────────────────────────────────────────────────────────
cat > "$RESULTS_FILE" <<JSONEOF
{
  "test_id": "SUBGHZ-${LABEL}-${TIMESTAMP}",
  "timestamp": "$(date -Iseconds)",
  "device_label": "${LABEL}",
  "configuration_state": ${STATE},
  "frequency_mhz": "${DETECTED_FREQ}",
  "capture_count": ${CAPTURE_COUNT},
  "rolling_code_present": "${ROLLING_CODE}",
  "replay_attack_result": "${REPLAY_RESULT}",
  "jamming_result": "${JAM_RESULT:-NOT_TESTED}",
  "jamming_disruption_seconds": ${JAM_DURATION:-0},
  "owasp_category": "I1",
  "etsi_provision": "5.5",
  "findings": [
$( [[ "$ROLLING_CODE" == "NO" ]] && echo '    {"severity": "HIGH", "issue": "Static Sub-GHz signal — no rolling code", "owasp": "I1", "etsi": "5.5"},' )
$( [[ "$REPLAY_RESULT" == "SUCCESS" ]] && echo '    {"severity": "CRITICAL", "issue": "Replay attack succeeded", "owasp": "I1", "etsi": "5.5"},' )
$( [[ "${JAM_RESULT:-}" == "SUCCESS" ]] && echo '    {"severity": "MEDIUM", "issue": "Sustained jamming caused persistent DoS (>30s)", "owasp": "I8", "etsi": "5.13"},' )
    {"severity": "INFO", "issue": "Test complete", "owasp": "N/A", "etsi": "N/A"}
  ]
}
JSONEOF

log ""
log "===== Sub-GHz Assessment Complete ====="
log "Results saved: $RESULTS_FILE"
log "Capture files: $CAPTURE_DIR"
log ""
log "Next steps:"
log "  - If rolling code absent, document exact protocol via Flipper's protocol database"
log "  - Cross-reference findings with score_device.py for three-state comparison"
log "  - If novel/undocumented vulnerability found, use templates/vuln-report.md"
