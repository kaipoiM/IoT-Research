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
    --rtsp-port)    RTSP_PORT="$2";       shift 2 ;;
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
#   Aqara 2K Camera — Phase 1 recon (2026-09-17) found local RTSP OPEN on
#     TCP/8554 (non-standard port, not the RTSP default of 554) with full
#     OPTIONS/DESCRIBE/SETUP/PLAY method support. The device is NOT purely
#     cloud-gated as initially assumed — run this script with
#     --rtsp-port 8554 against this device, or local RTSP creds will be
#     silently skipped (port-discovery scan below only checks $RTSP_PORT,
#     which defaults to 554).
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
  -Pn \
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
# NOTE ON METHOD: this step uses ffprobe (FFmpeg's RTSP client), not curl.
# curl's RTSP support is thin and was empirically confirmed unreliable for
# authentication testing during this research (2026-10-07): curl reported
# HTTP 200 on a DESCRIBE with garbage credentials against this exact camera,
# while ffprobe — against the identical URL — correctly got a 401 Unauthorized
# from the server. curl's RTSP engine does not faithfully relay real server
# auth status here, so it cannot be trusted for this test. ffprobe's RTSP
# client is mature (backs ffmpeg/ffplay) and its result was independently
# verified to match the real server behavior.
#
# We run ONE control probe with a deliberately wrong/garbage credential before
# the real credential list, to distinguish two different findings that look
# identical if you only test "do known-default creds work":
#   - Control succeeds too  -> NO AUTHENTICATION is enforced on the local RTSP
#     stream at all (OWASP I2 / ETSI 5.1 & 5.6) — credentials are irrelevant,
#     the stream is open to anyone on the local segment.
#   - Control fails (401), default creds succeed -> genuine weak/default
#     credential finding (OWASP I1 / ETSI 5.1).
if echo "$OPEN_PORTS" | grep -q "^${RTSP_PORT}$"; then
  log ""
  log "── Step 5: RTSP Stream Access Test (port $RTSP_PORT) ──"
  log "NOTE: Aqara camera confirmed exposing local RTSP on TCP/8554 per Phase 1"
  log "recon (2026-09-17) — this is NOT the RTSP default port 554. If testing"
  log "this device, confirm --rtsp-port 8554 was passed on the command line."

  if ! command -v ffprobe &>/dev/null; then
    log "⚠  ffprobe not found — RTSP credential test requires it (curl's RTSP"
    log "   auth handling is unreliable, confirmed during this research)."
    log "   Install: sudo apt install ffmpeg"
  else
    log "Probing via ffprobe/RTSP DESCRIBE (not curl — curl's RTSP auth handling"
    log "was confirmed unreliable against this device on 2026-10-07)."

    rtsp_probe() {
      # Echoes ACCESS_GRANTED, REJECTED_401, or UNKNOWN:<tail of error output>
      local url="$1"
      local out
      out=$(timeout 6 ffprobe -rtsp_transport tcp -v error \
        -show_entries stream=codec_name,width,height \
        -of default=noprint_wrappers=1 "$url" 2>&1)
      if echo "$out" | grep -qi "401"; then
        echo "REJECTED_401"
      elif echo "$out" | grep -qi "codec_name="; then
        echo "ACCESS_GRANTED"
      else
        echo "UNKNOWN:$(echo "$out" | tail -1)"
      fi
    }

    # ── Control probe: deliberately wrong credential, root path ──────────────
    CONTROL_USER="nosuchuser_$$"
    CONTROL_PASS="wrongpass_$(date +%s)"
    CONTROL_URL="rtsp://${CONTROL_USER}:${CONTROL_PASS}@${TARGET}:${RTSP_PORT}/"
    CONTROL_RESULT=$(rtsp_probe "$CONTROL_URL")
    log ""
    log "Control probe (garbage credentials, root path): $CONTROL_RESULT"
    if [[ "$CONTROL_RESULT" == "ACCESS_GRANTED" ]]; then
      log "⚠  Control probe SUCCEEDED with garbage credentials — this RTSP endpoint"
      log "   does not enforce authentication at all. Any credential result below"
      log "   is a consequence of this, not evidence of weak/default creds."
      echo "NO_AUTH_ENFORCED: rtsp $TARGET $RTSP_PORT (ffprobe succeeded with garbage creds: $CONTROL_USER:$CONTROL_PASS)" >> "$LOG_FILE"
    elif [[ "$CONTROL_RESULT" == "REJECTED_401" ]]; then
      log "Control probe correctly rejected (401) — auth appears enforced."
      log "Any credential below that is ACCESS_GRANTED is a genuine finding."
    else
      log "Control probe returned unexpected result ($CONTROL_RESULT) — treat results below with caution."
    fi

    for CRED in "admin:admin" "admin:" "admin:1234" "admin:password" "root:root" ":"; do
      USER="${CRED%%:*}"
      PASS="${CRED##*:}"
      RTSP_URL="rtsp://${USER}:${PASS}@${TARGET}:${RTSP_PORT}/"
      RESULT=$(rtsp_probe "$RTSP_URL")
      if [[ "$RESULT" == "ACCESS_GRANTED" ]]; then
        success "RTSP stream access granted — ${USER}:${PASS}"
        echo "CREDENTIAL_FOUND: rtsp $TARGET $USER $PASS /" >> "$LOG_FILE"
      else
        log "  ${USER}:${PASS} -> $RESULT"
      fi
    done

    if [[ "$CONTROL_RESULT" == "ACCESS_GRANTED" ]]; then
      log ""
      log "⚠  Reminder: control probe above succeeded with garbage credentials."
      log "   Treat any CREDENTIAL_FOUND lines as 'no auth enforced', not 'weak creds'."
    fi
  fi
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
FOUND_COUNT=$(grep -c "CREDENTIAL_FOUND" "$LOG_FILE" 2>/dev/null) || FOUND_COUNT=0
NO_AUTH_COUNT=$(grep -c "NO_AUTH_ENFORCED" "$LOG_FILE" 2>/dev/null) || NO_AUTH_COUNT=0
log "Credentials found: $FOUND_COUNT"

if [[ "$NO_AUTH_COUNT" -gt 0 ]]; then
  log "⚠  RESULT: RTSP endpoint enforces NO AUTHENTICATION at all (control probe"
  log "   with garbage credentials succeeded). The $FOUND_COUNT CREDENTIAL_FOUND"
  log "   line(s) above are a consequence of this, not evidence of weak/default"
  log "   credentials specifically — report this as a no-auth finding."
  log "   OWASP: I2 (Insecure Network Services) / I10 (Lack of Physical Hardening"
  log "   context N/A — this is network-exposed, unauthenticated media access)"
  log "   ETSI:  Provision 5.1 & 5.6 violation (no authentication mechanism on"
  log "   a network-facing service)"
elif [[ "$FOUND_COUNT" -gt 0 ]]; then
  log "⚠  RESULT: Default/weak credential(s) accepted (control probe with"
  log "   garbage credentials was correctly rejected — this is a genuine"
  log "   credential-strength finding, not a no-auth artifact)"
  log "   OWASP: I1 (Weak, Guessable, or Hardcoded Passwords)"
  log "   ETSI:  Provision 5.1 violation (no universal default passwords)"
else
  log "✓  No default credentials accepted on tested surfaces."
  log "   If device is cloud-gated (no local login), document this explicitly —"
  log "   it is a valid State 1 result, not a null test."
fi

log "Next: proceed to Phase 3 (scripts/network/mitm_arp.sh)"
