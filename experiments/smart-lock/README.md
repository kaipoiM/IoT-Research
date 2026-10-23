# Experiment: Smart Lock — KUCACCI Smart Door Lock

## Device Info

| Field | Value |
|-------|-------|
| **Model** | KUCACCI Smart Door Lock (fingerprint/keypad model, e.g. H15/Z-series) |
| **Firmware** | TBD — record before each state |
| **Protocol** | Bluetooth LE (TTLock app control), RFID key fob, keypad (physical PIN entry), optional WiFi via KUCACCI Gateway (sold separately) for remote access |
| **Access Methods** | Fingerprint, BLE app (TTLock), keypad passcode, RFID fob, mechanical backup key |
| **Manufacturer Claims** | AES-256 encryption for fingerprint/user data (per listing) — verify claim scope (data-at-rest vs. BLE transport) during testing |
| **Known CVEs** | None published as of research start — no NVD/CVE entries found for KUCACCI specifically. This is itself notable: absence of public disclosure does not indicate absence of vulnerabilities for a budget/white-label device, and lack of a security research history increases the value of first-party testing. |

**Note:** KUCACCI locks are commonly built on the TTLock white-label platform (per manufacturer app references). If confirmed during recon, prior TTLock/generic BLE smart lock research (e.g., "Just Works" pairing weaknesses, replay of BLE unlock commands) may apply and should be cited if verified against this specific device's BLE implementation.

---

## Attack Plan — All Three States

### State 1: Factory Default
All phases executed. Device out-of-box, default pairing/credentials unchanged.

### State 2: Vendor-Recommended Hardening
- Apply vendor security settings (if available in companion app)
- Update firmware to latest version
- Re-test Phases 2–4 (RF/BLE attack surface rarely changes via app settings alone)

### State 3: Best-Practice Hardening
- Limited applicability — RF/hardware-level security is largely fixed at manufacture
- Document any user-configurable options (e.g., disabling RFID fallback, BLE range limiting)
- Re-test Phases 2–4

*Note: per methodology, State 3 has limited applicability for this device class since core vulnerabilities are hardware/protocol-level, not configuration-level.*

---

## Test Phases

### Phase 1: Reconnaissance — Protocol Identification
- **Script:** `scripts/rf/ble_scan.sh --label lock-s1` (discovery mode, no target MAC yet)
- **Captures:** BLE advertisement identification of the lock, confirmation of TTLock or proprietary GATT service UUIDs
- **Also confirm:** Whether device transmits on Sub-GHz at all (KUCACCI's primary control path is BLE + optional WiFi gateway, not Sub-GHz RF like traditional garage-door-style remotes) — if a Sub-GHz signal is found (e.g., for a separate remote fob accessory), run `scripts/rf/subghz_capture.sh` per the camera/sensor pattern

### Phase 2: BLE Pairing & Communication Security
- **Script:** `scripts/rf/ble_scan.sh --target-mac <MAC> --label lock-s1`
- **Tests:** Pairing mode ("Just Works" detection), GATT service/characteristic enumeration, whether unlock commands are encrypted or sent in cleartext over BLE
- **Criteria:** Unauthenticated pairing succeeds, OR unlock command is replayable without pairing, OR GATT characteristics expose fingerprint/user data without authentication

### Phase 3: BLE Replay & Range Testing
- **Script:** `scripts/rf/ble_scan.sh --target-mac <MAC> --label lock-s1 --range-test`
- **Tests:** Capture and replay of BLE unlock command; effective range vs. manufacturer's implied "at the door" proximity assumption
- **Criteria:** Captured unlock command successfully re-triggers lock action; range exceeds ~10m BLE norm with directional antenna (Flipper Zero ESP32 module)

### Phase 4: Keypad & RFID Attack Surface
- **Tools:** Manual testing, Flipper Zero (RFID/NFC read-clone if 125kHz/13.56MHz fob confirmed)
- **Tests:** Keypad brute-force feasibility (lockout behavior after failed attempts — note "50 times maximum to unlock" per battery-failure spec, verify if this applies to failed PIN attempts too), anti-peep/scramble code effectiveness, RFID fob cloning
- **Criteria:** PIN brute-forceable within reasonable time (no lockout), OR RFID fob successfully cloned via Flipper Zero

### Phase 5: Physical Security / Hardware Interface
- **Tools:** Visual inspection, Bus Pirate 5 (if debug pins accessible)
- **Check for:** Exposed UART/JTAG on internal PCB, tamper-evidence, mechanical bypass (lock bumping/shimming — note manufacturer's included physical backup key as an attack surface), battery-removal/USB emergency power port as unauthenticated bypass path

---

## Test Log Files

Store all test logs in `logs/` using the standardized JSON schema:
`templates/test-log.json`

Naming convention: `LOCK-S{state}-{ATTACK_CODE}-{SEQ}_{TIMESTAMP}.json`

Examples:
- `LOCK-S1-REPLAY-001_20260201_143022.json`
- `LOCK-S1-BLE-001_20260201_150210.json`
- `LOCK-S1-JAM-001_20260201_153045.json`

---

## Success Metrics

| Test | Criteria |
|------|---------|
| BLE Pairing | Authenticated pairing required (Yes/No) |
| BLE Replay | Captured unlock command triggers lock action (Yes/No) |
| BLE Range | Exploitable distance (meters) vs. ~10m manufacturer-implied range |
| Keypad Brute Force | PIN attack feasible without lockout (Yes/No), time to compromise |
| RFID Cloning | Fob successfully cloned (Yes/No) |
| Physical Bypass | Mechanical/backup-access bypass found (Yes/No) |
| Mitigation | Attack success rate change: State 1 → State 2 → State 3 |

---

## Notes / Observations

> Add notes here during testing.

- [ ] Record firmware version before starting each state
- [ ] Confirm primary control protocol is BLE-only (no Sub-GHz remote fob accessory in this configuration)
- [ ] Note whether TTLock (or equivalent) app forces a security PIN/passphrase during initial setup
- [ ] Test RFID/NFC fob cloning via Flipper Zero if fob access method is enabled
- [ ] Verify manufacturer's AES-256 encryption claim actually covers BLE transport, not just at-rest fingerprint storage
- [ ] Document lockout behavior (if any) after repeated failed keypad attempts
