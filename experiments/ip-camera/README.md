# Experiment: IP Camera — TP-Link Tapo C-Series

## Device Info

| Field | Value |
|-------|-------|
| **Model** | TP-Link Tapo C-Series (e.g., C210 / C220) |
| **Firmware** | TBD — record before each state |
| **Protocol** | HTTPS, RTSP, MQTT (cloud), 2.4GHz WiFi |
| **Known CVEs** | CVE-2025-15557 (improper certificate validation) |

---

## Attack Plan — All Three States

### State 1: Factory Default
All phases executed. Device out-of-box, default credentials unchanged.

### State 2: Vendor-Recommended Hardening
- Change admin password per TP-Link guide
- Apply all firmware updates via Tapo app
- Enable two-step verification if available
- Re-test Phases 2–4

### State 3: Best-Practice Hardening
- Strong unique password (20+ chars, generated)
- Network segmentation (IoT VLAN, block cloud egress)
- Disable RTSP if not required
- Certificate pinning enforcement where possible
- Re-test Phases 2–4

---

## Test Phases

### Phase 1: Reconnaissance (Passive)
- **Script:** `scripts/network/recon.sh --label cam`
- **Duration:** 24-hour traffic baseline
- **Captures:** Open ports, services, DNS queries, traffic volume

### Phase 2: Credential Attack
- **Script:** `scripts/network/credential_test.sh --label cam-s1`
- **Default creds to try:** admin/admin, admin/tplink, admin/1234, admin/(blank)
- **RTSP paths:** `/stream1`, `/cam/realmonitor`, `/user=admin&password=`
- **Criteria:** Unauthorized admin access gained

### Phase 3: MITM + SSL Interception
- **Script:** `scripts/network/mitm_arp.sh --label cam-s1`
- **Tests CVE-2025-15557** directly — improper certificate validation in Tapo devices
- **Criteria:** Credentials or video stream intercepted via SSLsplit

### Phase 4: Privacy Analysis
- **Script:** `scripts/analysis/traffic_baseline.py --label cam-s1`
- **Cloud endpoints:** tplinkcloud.com, tapobeta.tp-link.com
- **Criteria:** Volume of data sent, tracking domains contacted

### Phase 5: Firmware Analysis
- **Tools:** binwalk, strings, Ghidra (optional)
- **Source:** Download from TP-Link firmware portal OR UART extraction (Bus Pirate 5)
- **Check for:** Hardcoded credentials, debug interfaces, SSL/TLS misuse (per Liu et al. 2024)

---

## Test Log Files

Store all test logs in `logs/` using the standardized JSON schema:
`templates/test-log.json`

Naming convention: `CAM-S{state}-{ATTACK_CODE}-{SEQ}_{TIMESTAMP}.json`

Examples:
- `CAM-S1-CRED-001_20260115_143022.json`
- `CAM-S2-MITM-001_20260116_091533.json`
- `CAM-S3-TLS-001_20260117_103045.json`

---

## Success Metrics

| Test | Criteria |
|------|---------|
| Credential Attack | Unauthorized admin access gained (Yes/No) |
| MITM/TLS | Credentials or stream content intercepted (Yes/No) |
| Privacy | Tracking domains contacted (Count), data volume (MB) |
| Firmware | Hardcoded credentials found (Yes/No) |
| Mitigation | Attack success rate change: State 1 → State 2 → State 3 |

---

## Notes / Observations

> Add notes here during testing.

- [ ] Record firmware version before starting each state
- [ ] Document whether Tapo app forces password change on first setup
- [ ] Note whether CVE-2025-15557 is patched in current firmware
- [ ] Check if RTSP requires authentication or streams without credentials
