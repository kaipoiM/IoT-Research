#!/usr/bin/env bash
# =============================================================================
# credential_test.sh — Default Credential & Brute-Force Testing
# IoT Security Research | Phase 2: Credential Attack
# =============================================================================
# Checks for default/weak credentials across HTTP(S), SSH, Telnet, and RTSP
# endpoints, then optionally runs Hydra for rate-limited brute force.
#
# Device-agnostic by design — default credential list draws from Mirai source,
# Shodan default-password lists, and common vendor defaults. Add device-specific
# entries via --extra-creds (see notes below for current target devices).
#
# Usage:
#   sudo bash credential_test.sh --target 192.168.100.X --label cam-s1 \
#                                --out experiments/ip-camera/logs/ [--brute]
#
# Requires: curl, nmap, hydra (optional for brute force)
# =============================================================================

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET=""
LABEL="device"
OUT_DIR="./output"
BRUTE_FORCE=false
EXTRA_CREDS_FILE=""
HTTP_PORT=80
HTTPS_PORT=443
SSH_PORT=22
TELNET_PORT=23
RTSP_PORT=554

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)       TARGET="$2";          shift 2 ;;
    --label)        LABEL="$2";           shift 2 ;;
    --out)          OUT_DIR="$2";         shift 2 ;;
    --http-port)    HTTP_PORT="$2";       shift 2 ;;
    --extra-creds)  EXTRA_CREDS_FILE="$2"; shift 2 ;;
    --brute)        BRUTE_FORCE=true;     shift ;;
    *) echo "[ERROR] Unknown argument: $1"; exit 1 ;;
  esac
done

[[ -z "$TARGET" ]] && { echo "[ERROR] --target is required"; exit 1; }

mkdir -p "$OUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$OUT_DIR/creds_${LABEL}_${TIMESTAMP}.log"

log() { echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG_FILE"; }
success() { echo "[$(date +%H:%M:%S)] ✓ SUCCESS: $*" | tee -a "$LOG_FILE"; }
fail()    { echo "[$(date +%H:%M:%S)] ✗ FAILED : $*" | tee -a "$LOG_FILE"; }

# ── Default credential pairs (generic IoT defaults) ───────────────────────────
# Sources: Mirai source code, Shodan, common vendor defaults, CVE database
#
# NOTE ON CURRENT TEST DEVICES:
#   Aqara 2K Camera — local admin credentials are not publicly documented;
#     device is cloud-account-gated by design. Test for exposed local
#     interfaces/services rather than assuming a local admin login exists.
#   LG TV (webOS)   — no local HTTP admin login by default; focus credential
#     testing on any exposed local services (e.g., LG ThinQ/webOS dev mode
#     if enabled) rather than a login form.
#   KUCACCI Lock    — no network-exposed credential surface (BLE/keypad only);
#     this script does not apply — use scripts/rf/ble_scan.sh instead.
#
# Add device/vendor-specific pairs at runtime via --extra-creds <file>
# (format: user:pass, one per line) rather than hardcoding a single vendor here.
DEFAULT_CREDS=(
  "admin:admin"
  "admin:password"
  "admin:1234"
  "admin:12345"
  "admin:123456"
  "admin:admin123"
  "admin:"
  "root:root"
  "root:admin"
  "root:password"
  "root:toor"
  "root:"
  "user:user"
  "user:password"
  "guest:guest"
  "guest:"
  # Generic camera defaults
  "admin:ipcam"
  "admin:camera"
  # Mirai-sourced defaults (Antonakakis et al. 2017 [4])
  "666666:666666"
  "888888:888888"
  "support:support"
  "default:default"
  "service:service"
  "supervisor:supervisor"
)

if [[ -n "$EXTRA_CREDS_FILE" && -f "$EXTRA_CREDS_FILE" ]]; then
  log "Loading additional credentials from $EXTRA_CREDS_FILE"
  while IFS= read -r line; do
    [[ -n "$line" ]] && DEFAULT_CREDS+=("$line")
  done < "$EXTRA_CREDS_FILE"
fi

log "===== Credential Testing: $TARGET ====="
log "Loaded ${#DEFAULT_CREDS[@]} credential pairs"
log ""

# ── Step 1: Port/service discovery ────────────────────────────────────────────
log "── Step 1: Service Discovery ──"
OPEN_PORTS=$(nmap -p "$HTTP_PORT,$HTTPS_PORT,$SSH_PORT,$TELNET_PORT,$RTSP_PORT" \
  -oG - "$TARGET" 2>/dev/null | grep -oP '\d+/open' | grep -oP '^\d+' || true)
log "Open relevant ports: ${OPEN_PORTS:-none found}"

# ── Step 2: HTTP(S) admin login test ──────────────────────────────────────────
if echo "$OPEN_PORTS" | grep -qE "^($HTTP_PORT|$HTTPS_PORT)$"; then
  log ""
  log "── Step 2: HTTP(S) Login Test ──"
  for CRED in "${DEFAULT_CREDS[@]}"; do
    USER="${CRED%%:*}"
    PASS="${CRED##*:}"
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
      --connect-timeout 3 \
      -u "${USER}:${PASS}" \
      "http://${TARGET}:${HTTP_PORT}/" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" == "200" ]]; then
      success "HTTP login accepted — ${USER}:${PASS}"
      echo "CREDENTIAL_FOUND: http $TARGET $USER $PASS" >> "$LOG_FILE"
    fi
  done
else
  log "No HTTP(S) admin interface exposed — consistent with cloud-gated devices (e.g., Aqara app-only auth)"
fi

# ── Step 3: SSH test (if hydra available) ─────────────────────────────────────
if echo "$OPEN_PORTS" | grep -q "^${SSH_PORT}$" && command -v hydra &>/dev/null; then
  log ""
  log "── Step 3: SSH Default Credential Test ──"
  printf '%s\n' "${DEFAULT_CREDS[@]}" | sed 's|:|/|' > /tmp/ssh_creds_$$
  hydra -C /tmp/ssh_creds_$$ -t 4 -T 3 ssh://"$TARGET":"$SSH_PORT" \
    2>/dev/null | tee -a "$LOG_FILE" || true
  rm -f /tmp/ssh_creds_$$
fi

# ── Step 4: Telnet test (legacy IoT protocol) ─────────────────────────────────
if echo "$OPEN_PORTS" | grep -q "^${TELNET_PORT}$"; then
  log ""
  log "── Step 4: Telnet Default Credential Test ──"
  log "⚠  Telnet found open — this is a CRITICAL finding (plaintext protocol)"
  echo "CRITICAL_FINDING: telnet_open $TARGET:$TELNET_PORT" >> "$LOG_FILE"

  if command -v hydra &>/dev/null; then
    printf '%s\n' "${DEFAULT_CREDS[@]}" | sed 's|:|/|' > /tmp/telnet_creds_$$
    hydra -C /tmp/telnet_creds_$$ -t 4 -T 3 telnet://"$TARGET":"$TELNET_PORT" \
      2>/dev/null | tee -a "$LOG_FILE" || true
    rm -f /tmp/telnet_creds_$$
  fi
fi

# ── Step 5: RTSP stream access (IP cameras) ───────────────────────────────────
if echo "$OPEN_PORTS" | grep -q "^${RTSP_PORT}$"; then
  log ""
  log "── Step 5: RTSP Stream Access Test ──"
  log "NOTE: Aqara cameras are cloud-account-gated by design and may not expose"
  log "local RTSP. If port 554 is closed, this is expected — document as such"
  log "rather than a test failure, and rely on Phase 3 (MITM/cloud interception) instead."

  RTSP_PATHS=(
    "/"
    "/stream"
    "/stream1"
    "/live"
    "/h264"
    "/video.mp4"
    "/cam/realmonitor"
    "/user=admin&password=&channel=1&stream=0.sdp"
    "/onvif1"
  )

  for CRED in "admin:admin" "admin:" "admin:1234" "admin:password" ":"; do
    USER="${CRED%%:*}"
    PASS="${CRED##*:}"
    for PATH in "${RTSP_PATHS[@]}"; do
      RTSP_URL="rtsp://${USER}:${PASS}@${TARGET}:${RTSP_PORT}${PATH}"
      HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        --connect-timeout 3 \
        -X OPTIONS \
        "$RTSP_URL" 2>/dev/null || echo "000")
      if [[ "$HTTP_CODE" == "200" ]]; then
        success "RTSP stream accessible — $RTSP_URL"
        echo "CREDENTIAL_FOUND: rtsp $TARGET $USER $PASS $PATH" >> "$LOG_FILE"
      fi
    done
  done
else
  log "RTSP port closed/filtered — expected for cloud-only camera architectures"
fi

# ── Step 6: Optional Hydra brute force ────────────────────────────────────────
if [[ "$BRUTE_FORCE" == "true" ]]; then
  log ""
  log "── Step 6: Hydra Brute Force (rate-limited) ──"

  if ! command -v hydra &>/dev/null; then
    log "Hydra not found. Skipping brute force. Install: apt install hydra"
  else
    # Use a small, IoT-targeted wordlist (not rockyou — too large)
    WORDLIST="/usr/share/wordlists/metasploit/http_default_pass.txt"
    USERLIST="/usr/share/wordlists/metasploit/http_default_users.txt"

    if [[ -f "$WORDLIST" && -f "$USERLIST" ]]; then
      HYDRA_OUT="$OUT_DIR/hydra_${LABEL}_${TIMESTAMP}.txt"
      hydra -L "$USERLIST" -P "$WORDLIST" \
        -t 4 -w 3 \
        -o "$HYDRA_OUT" \
        http-post-form://"$TARGET":"$HTTP_PORT"/admin:username=^USER^&password=^PASS^:F=incorrect \
        2>&1 | tail -5 | tee -a "$LOG_FILE"
      log "Hydra results: $HYDRA_OUT"
    else
      log "Wordlists not found at $WORDLIST — skipping Hydra."
    fi
  fi
fi

# ── Results summary ────────────────────────────────────────────────────────────
log ""
log "===== Credential Test Complete ====="
FOUND_COUNT=$(grep -c "CREDENTIAL_FOUND" "$LOG_FILE" 2>/dev/null || echo 0)
log "Credentials found: $FOUND_COUNT"

if [[ "$FOUND_COUNT" -gt 0 ]]; then
  log "⚠  RESULT: Default/weak credential(s) accepted"
  log "   OWASP: I1 (Weak, Guessable, or Hardcoded Passwords)"
  log "   ETSI:  Provision 5.1 violation (no universal default passwords)"
else
  log "✓  No default credentials accepted on tested surfaces."
  log "   If device is cloud-gated (no local login), document this explicitly —"
  log "   it is a valid State 1 result, not a null test."
fi

log "Next: proceed to Phase 3 (scripts/network/mitm_arp.sh)"
