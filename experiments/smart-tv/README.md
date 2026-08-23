# Experiment: Smart TV — LG 43UK6550PUB

## Device Info

| Field | Value |
|-------|-------|
| **Model** | LG 43UK6550PUB (2018 UK-series, 4K UHD) |
| **Platform** | webOS 4.0 (shipped version — confirm current version post-updates before testing) |
| **Firmware** | TBD — record exact build number before each state via Settings > General > About This TV |
| **Protocol** | HTTPS/TLS, WiFi 2.4/5GHz, UPnP/DLNA, Bluetooth 4.2 (remote/audio pairing) |
| **Known CVEs** | **CVE-2023-6317 / -6318 / -6319 / -6320** (Bitdefender disclosure, reported Nov. 2023, patched by LG Mar. 22, 2024). Affects webOS 4.9.7 through 7.3.1-43 — this model's 4.0 lineage falls within the affected range. Chain: CVE-2023-6317 bypasses PIN verification to add a privileged user profile via the phone-connectivity service without user interaction; CVE-2023-6318 escalates that access to full root; CVE-2023-6319 achieves command injection via the music-lyrics display library; CVE-2023-6320 achieves authenticated command injection via the `setVlanStaticAddress` API endpoint as the `dbus` user. A public PoC exists (`rootmytv.py`, illixion) that stands up a root telnet server on vulnerable units — useful as a direct test of whether this specific TV's current firmware has actually applied LG's patch. |

**This is the core research question for this device:** LG shipped a fix in March 2024, but this specific unit's patch status is unverified until tested. A successful `rootmytv.py`-style compromise in State 1 (default/unpatched-if-never-updated) directly answers whether "vendor patched it" translated into "this consumer's TV is actually protected" — which is exactly the temporal/current-generation gap this research is built around (Section VIII, Gap C).

---

## Attack Plan — All Three States

### State 1: Factory Default
All phases executed. TV out-of-box, default account/pairing settings unchanged, all data collection features (ACR/viewing history) left at default.

### State 2: Vendor-Recommended Hardening
- Apply vendor-recommended privacy settings (disable ACR/viewing data collection per LG's own settings menu)
- Apply all firmware/webOS updates
- Re-test Phases 2, 3, 5

### State 3: Best-Practice Hardening
- Network segmentation (isolated IoT VLAN, blocked cloud telemetry egress where functionality allows)
- DNS-level blocking of known tracking/analytics domains
- Disable unnecessary services (UPnP, unused smart features)
- Re-test Phases 2, 3, 5

---

## Test Phases

### Phase 1: Baseline Data Collection
- **Script:** `scripts/analysis/traffic_baseline.py --label tv`
- **Duration:** 48-hour normal usage monitoring
- **Captures:** Tracking/analytics domains contacted, data volume, ACR (automatic content recognition) traffic patterns

### Phase 2: Evil Twin Attack
- **Script:** WiFi Pineapple configuration per `docs/legal-ethics.md` SSID restrictions
- **Tests:** Whether TV connects to rogue AP mimicking known network, credential/traffic capture upon forced reconnection

### Phase 3: Application Security — CVE-2023-6317/6318/6319/6320 Chain
- **Tests:**
  1. Record current webOS build number (Settings > General > About This TV) before attempting anything
  2. Check NVD/LG's own advisory to determine the exact patched build number
  3. If unpatched: attempt the documented PIN-bypass → privileged account creation (CVE-2023-6317) via the phone-connectivity/secondscreen.gateway service
  4. If successful, attempt privilege escalation to root (CVE-2023-6318) and/or command injection via the lyrics-display path (CVE-2023-6319)
  5. Document whether firmware auto-update (if enabled) had already silently applied the fix, vs. requiring manual "Check for Update"
- **Also tests:** General LG account/app authentication mechanism and update mechanism signature verification
- **Criteria:** Root access achieved (Yes/No), build number vs. known-patched version, whether auto-update closed the gap before testing began

### Phase 4: UPnP/DLNA Fuzzing
- **Tools:** Kali (Boofuzz or custom scripts)
- **Tests:** Malformed UPnP/DLNA packet injection
- **Criteria:** Service crash, unexpected behavior, or unauthorized control gained

### Phase 5: Privacy Quantification
- **Script:** `scripts/analysis/traffic_baseline.py --label tv-s1` (reused across states for comparison)
- **Tests:** Data exfiltration volume, DNS filtering effectiveness in State 3
- **Criteria:** Tracking domain count and data volume, before/after hardening

---

## Test Log Files

Store all test logs in `logs/` using the standardized JSON schema:
`templates/test-log.json`

Naming convention: `TV-S{state}-{ATTACK_CODE}-{SEQ}_{TIMESTAMP}.json`

Examples:
- `TV-S1-TWIN-001_20260201_143022.json`
- `TV-S1-PRIV-001_20260203_091533.json`

---

## Success Metrics

| Test | Criteria |
|------|---------|
| Evil Twin | TV connects to rogue AP (Yes/No), credentials captured |
| App Security | CVE-2023-6317 chain succeeds (Yes/No), root access achieved (Yes/No), build number vs. patched version |
| UPnP Fuzzing | Crash or unauthorized control achieved (Yes/No) |
| Privacy | Tracking domains contacted (Count), data sent (MB) |
| Mitigation | Attack success rate / data volume change: State 1 → State 2 → State 3 |

---

## Notes / Observations

> Add notes here during testing.

- [ ] Record exact webOS build number before starting each state (Settings > General > About This TV)
- [ ] Determine LG's official patched build number for CVE-2023-6317/6318/6319/6320 from LG's security advisory before testing
- [ ] Test `rootmytv.py` (illixion) against State 1 BEFORE applying any updates — this is the highest-value test on this device
- [ ] If root achieved, document full extent (persistent telnet root access per the PoC's design) before restoring to a clean/patched state
- [ ] Document ACR opt-out location in settings menu (verify it actually stops network traffic, not just UI toggle)
- [ ] Note any smart assistant (e.g., built-in voice) microphone behavior and associated privacy controls
- [ ] If patched already (auto-update applied before hands-on testing began), document this explicitly as a finding — "vendor patch reached this consumer unit" is itself a data point for Section VIII Gap C
