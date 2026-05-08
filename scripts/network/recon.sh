#!/usr/bin/env bash
# =============================================================================
# recon.sh — Passive Network Discovery & Traffic Baseline
# IoT Security Research | Phase 1: Reconnaissance
# =============================================================================
# Usage:
#   sudo bash recon.sh --iface eth0 --target 192.168.100.X --duration 3600 --out experiments/ip-camera/logs/
#
# Requires: nmap, tcpdump, arp-scan, tshark, netdiscover
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
IFACE="eth0"
TARGET=""
NETWORK="192.168.100.0/24"
DURATION=3600       # seconds for passive traffic capture
OUT_DIR="./output"
DEVICE_LABEL="device"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --iface)    IFACE="$2";         shift 2 ;;
    --target)   TARGET="$2";        shift 2 ;;
    --network)  NETWORK="$2";       shift 2 ;;
    --duration) DURATION="$2";      shift 2 ;;
    --out)      OUT_DIR="$2";       shift 2 ;;
    --label)    DEVICE_LABEL="$2";  shift 2 ;;
    *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
  esac
done

mkdir -p "$OUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUT_DIR/recon_${DEVICE_LABEL}_${TIMESTAMP}.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }

log "===== IoT Recon Script Start ====="
log "Interface : $IFACE"
log "Network   : $NETWORK"
log "Target    : ${TARGET:-'(discover)'}"
log "Duration  : ${DURATION}s"
log "Output    : $OUT_DIR"

# ── Phase 1a: Network Discovery ───────────────────────────────────────────────
log ""
log "── Phase 1a: Network Discovery ──"

ARP_OUT="$OUT_DIR/arp_scan_${TIMESTAMP}.txt"
log "Running arp-scan on $NETWORK ..."
arp-scan --interface="$IFACE" "$NETWORK" 2>/dev/null | tee "$ARP_OUT" | grep -E "([0-9]{1,3}\.){3}" | tee -a "$LOG_FILE" || true
log "ARP scan results saved to: $ARP_OUT"

# ── Phase 1b: Port Scan & Service Detection ───────────────────────────────────
if [[ -n "$TARGET" ]]; then
  log ""
  log "── Phase 1b: Port Scan — $TARGET ──"
  NMAP_XML="$OUT_DIR/nmap_${DEVICE_LABEL}_${TIMESTAMP}.xml"
  NMAP_OUT="$OUT_DIR/nmap_${DEVICE_LABEL}_${TIMESTAMP}.txt"

  log "Full TCP SYN scan + service/version detection + default scripts ..."
  nmap -sS -sV -sC -O -p- \
    --open \
    --version-intensity 9 \
    -T4 \
    -oX "$NMAP_XML" \
    -oN "$NMAP_OUT" \
    "$TARGET" 2>&1 | tee -a "$LOG_FILE"

  log "Nmap results saved to: $NMAP_OUT"

  # UDP scan for common IoT services (MQTT 1883, CoAP 5683, mDNS 5353)
  log "UDP scan for common IoT ports ..."
  UDP_OUT="$OUT_DIR/nmap_udp_${DEVICE_LABEL}_${TIMESTAMP}.txt"
  nmap -sU -p 1883,5683,5353,123,161,1900 \
    --open -T4 \
    -oN "$UDP_OUT" \
    "$TARGET" 2>&1 | tee -a "$LOG_FILE"
fi

# ── Phase 1c: mDNS / Bonjour / SSDP Discovery ─────────────────────────────────
log ""
log "── Phase 1c: mDNS / SSDP Discovery ──"
MDNS_OUT="$OUT_DIR/mdns_${TIMESTAMP}.txt"

# avahi-browse for mDNS
if command -v avahi-browse &>/dev/null; then
  log "Querying mDNS services ..."
  timeout 30 avahi-browse -a -t 2>/dev/null | tee "$MDNS_OUT" || true
  log "mDNS results saved to: $MDNS_OUT"
fi

# SSDP discovery for UPnP devices
SSDP_OUT="$OUT_DIR/ssdp_${TIMESTAMP}.txt"
log "Sending SSDP M-SEARCH for UPnP devices ..."
python3 - <<'PYEOF' 2>/dev/null | tee "$SSDP_OUT" || true
import socket, time

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
msg = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    "MAN: \"ssdp:discover\"\r\n"
    "MX: 3\r\n"
    "ST: ssdp:all\r\n\r\n"
)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.settimeout(5)
sock.sendto(msg.encode(), (SSDP_ADDR, SSDP_PORT))
start = time.time()
while time.time() - start < 5:
    try:
        data, addr = sock.recvfrom(1024)
        print(f"[{addr[0]}] {data.decode(errors='ignore')[:200]}")
    except socket.timeout:
        break
PYEOF

# ── Phase 1d: Passive Traffic Baseline ────────────────────────────────────────
log ""
log "── Phase 1d: Passive Traffic Capture ($DURATION seconds) ──"
PCAP_FILE="$OUT_DIR/baseline_${DEVICE_LABEL}_${TIMESTAMP}.pcap"

CAPTURE_FILTER=""
if [[ -n "$TARGET" ]]; then
  CAPTURE_FILTER="host $TARGET"
  log "Capturing traffic for $TARGET only ..."
else
  log "Capturing all traffic on $IFACE (no target filter) ..."
fi

log "Traffic capture started. Will stop after ${DURATION}s."
log "Output: $PCAP_FILE"

tcpdump -i "$IFACE" \
  ${CAPTURE_FILTER:+-n "$CAPTURE_FILTER"} \
  -w "$PCAP_FILE" \
  -G "$DURATION" -W 1 \
  2>>"$LOG_FILE" &
TCPDUMP_PID=$!

# Progress indicator
ELAPSED=0
while [[ $ELAPSED -lt $DURATION ]]; do
  sleep 30
  ELAPSED=$((ELAPSED + 30))
  REMAINING=$((DURATION - ELAPSED))
  PKTS=$(tcpdump -r "$PCAP_FILE" --count 2>/dev/null | grep -oP '\d+ packets' | head -1 || echo "?")
  log "  Progress: ${ELAPSED}s elapsed, ${REMAINING}s remaining | $PKTS captured"
done

wait $TCPDUMP_PID 2>/dev/null || true
log "Capture complete: $PCAP_FILE"

# ── Summary ───────────────────────────────────────────────────────────────────
log ""
log "===== Recon Complete ====="
log "Files generated:"
ls -lh "$OUT_DIR/"*"$TIMESTAMP"* 2>/dev/null | tee -a "$LOG_FILE" || true
log ""
log "Next steps:"
log "  python scripts/analysis/pcap_parser.py --pcap $PCAP_FILE"
log "  python scripts/analysis/tls_checker.py --target $TARGET"
log "  bash scripts/network/credential_test.sh --target $TARGET"
