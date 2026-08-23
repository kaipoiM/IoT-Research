# Experiment: IP Camera — Aqara 2K Indoor/Outdoor Security Camera

## Device Info

| Field | Value |
|-------|-------|
| **Model** | Aqara 2K Indoor/Outdoor Security Camera |
| **Firmware** | TBD — record before each state |
| **Protocol** | HTTPS/TLS (cloud), RTSP (local, if enabled), WiFi 2.4GHz, HomeKit Secure Video (if applicable) |
| **Ecosystem** | Aqara Home app / Lumi United cloud platform |
| **Known CVEs / Advisories** | CVE-2026-50091 (hardcoded cryptographic keys in Aqara Home Android SDK — enables forgery of camera authentication signatures, pairing impersonation, and decryption of captured content from MITM position); CVE-2025-65293 and CVE-2025-65295 (Aqara Camera Hub G3 — command injection via malicious QR code, unsigned firmware updates) — verify applicability to this specific camera model vs. hub-only; broader 2026 disclosure of Aqara/Lumi cloud platform vulnerabilities (unauthenticated IAM/SSO gateway exposure, account takeover chain) |

**Note:** The hardcoded-key (CVE-2026-50091) and cloud platform vulnerabilities were disclosed against the Aqara ecosystem broadly (SDK + cloud), not confirmed device-specific to this exact camera model. Confirm current patch status via `security@aqara.com` advisories before testing, and treat pre-patch findings as historical baseline rather than assumed-present.

---

## Attack Plan — All Three States

### State 1: Factory Default
All phases executed. Device out-of-box, default credentials/pairing unchanged, cloud account freshly created for research.

### State 2: Vendor-Recommended Hardening
- Change admin/app account password per Aqara security guidance
- Apply all firmware updates via Aqara Home app
- Enable two-factor authentication on Aqara account if available
- Re-test Phases 2–4

### State 3: Best-Practice Hardening
- Strong unique password (20+ chars, generated) for Aqara account
- Network segmentation (IoT VLAN, restrict cloud egress where feasible without breaking function)
- Disable local RTSP/local streaming if not required
- Verify current firmware patches CVE-2026-50091 and related SDK key issues
- Re-test Phases 2–4

---

## Test Phases

### Phase 1: Reconnaissance (Passive)
- **Script:** `scripts/network/recon.sh --label cam`
- **Duration:** 24-hour traffic baseline
- **Captures:** Open ports, services, DNS queries, traffic volume, cloud endpoints contacted

### Phase 2: Credential Attack
- **Script:** `scripts/network/credential_test.sh --label cam-s1`
- **Default creds to try:** admin/admin, admin/(blank), common Aqara/Lumi defaults if local access exposed
- **Criteria:** Unauthorized admin access gained (local interface or account takeover)

### Phase 3: MITM + SSL Interception
- **Script:** `scripts/network/mitm_arp.sh --label cam-s1`
- **Directly tests:** Whether hardcoded SDK keys (CVE-2026-50091) permit decryption of intercepted traffic or forged authentication signatures
- **Criteria:** Credentials, authentication signatures, or video stream intercepted/forged via SSLsplit

### Phase 4: Privacy Analysis
- **Script:** `scripts/analysis/traffic_baseline.py --label cam-s1`
- **Cloud endpoints:** Aqara/Lumi cloud domains (identify via DNS capture — confirm current domains, historically i2.aqara.com and similar)
- **Criteria:** Volume of data sent, tracking domains contacted

### Phase 5: Firmware Analysis
- **Tools:** binwalk, strings, Ghidra (optional)
- **Source:** Aqara firmware update capture during OTA (via app-triggered update) OR UART extraction (Bus Pirate 5) if debug interface accessible
- **Check for:** Hardcoded credentials/keys (per CVE-2026-50091 pattern), firmware signature validation, SSL/TLS misuse (per Liu et al. 2024 [14])

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
| MITM/TLS | Credentials, auth signatures, or stream content intercepted/forged (Yes/No) |
| Privacy | Tracking domains contacted (Count), data volume (MB) |
| Firmware | Hardcoded credentials/keys found (Yes/No) |
| Mitigation | Attack success rate change: State 1 → State 2 → State 3 |

---

## Notes / Observations

> Add notes here during testing.

- [ ] Record firmware version before starting each state
- [ ] Confirm whether current firmware has patched CVE-2026-50091 (hardcoded SDK keys)
- [ ] Document whether Aqara Home app forces password change/2FA on first setup
- [ ] Check whether local RTSP/streaming is available or cloud-only by design
- [ ] Verify current Aqara cloud platform advisory status at time of testing (platform-side fixes may lag device-side)
