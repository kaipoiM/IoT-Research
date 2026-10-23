# Methodology

A reproducible, standards-aligned procedure for evaluating consumer IoT device security across three configuration states. Each device is tested in all three states with an identical phase sequence so results are directly comparable, and the difference between states is the measurement of interest.

---

## A. Test environment

| Equipment | Role | Configuration notes |
|-----------|------|---------------------|
| Parrot OS Security laptop | Network attack platform | Dedicated test machine; packet-capture capable; attack NIC bound explicitly per test |
| WiFi Pineapple Mark VII | Test AP / MITM position | SSID restricted to `IoTSecTest`; MAC allow-list enforced; PineAP and Karma disabled; disabled between tests |
| Flipper Zero (+ ESP32) | RF / BLE testing | Faraday bag for replay and jamming tests; low-power mode |
| HackRF One | Sub-GHz / Zigbee analysis | Shielded environment; power output minimized to functional levels |
| Bus Pirate 5 | Hardware / UART / firmware | Used for console access and firmware inspection in Phase 5 |
| Raspberry Pi 4B | Isolated AP (RF-only / offline tests) | hostapd + dnsmasq; no WAN uplink; used where a device can operate without internet |

### Network topology

The test network provides LAN isolation from the household in all configurations. Two topologies are used depending on whether the device under test can operate offline:

- **Fully isolated** (Raspberry Pi 4B AP, no WAN): used for devices that function without cloud connectivity, and for all RF-only testing. Verified before each session by confirming 100% packet loss to an external host from a connected client.
- **Controlled-internet** (WiFi Pineapple AP → router guest network → internet): required for cloud-dependent devices that cannot be provisioned or operated offline. The guest network provides client isolation from the household LAN; the Pineapple is the controlled MITM position between the device and its cloud. This path is used only where a device's cloud dependency makes full isolation impossible, and the reason is recorded per device.

The choice of topology per device is documented in that device's experiment record, including why controlled-internet was necessary where it was used.

---

## B. Device selection

Three Tier-1 devices span distinct categories and attack surfaces.

**1. IP camera — Aqara G100 Indoor/Outdoor Security Camera.** High privacy risk, common target, diverse attack surface spanning network, TLS, RTSP, and hardware/firmware. Cloud-dependent (Lumi United platform), which itself is a finding-relevant property.

**2. Smart TV — LG 43UK6550PUB (webOS).** Data-collection concerns and a large application-layer attack surface representative of consumer electronics. **Record the webOS build string before any firmware update** — the baseline build cannot be recovered afterward.

**3. Smart lock — KUCACCI Smart Door Lock (BLE / TTLock platform, keypad, RFID).** Physical-security implications; demonstrates the RF attack surface (BLE, sub-GHz, RFID).

All devices are researcher-owned, with ownership documented. Device substitutions from the original project plan (Aqara G100 replacing TP-Link Tapo; KUCACCI replacing eufy/Sifely) were made during procurement; attack vectors were re-scoped to each actual device.

---

## C. Three-state framework

| State | Definition | Purpose |
|-------|-----------|---------|
| **1 — Factory Default** | Out-of-box; default credentials unchanged; all features enabled; no segmentation | Worst-case baseline |
| **2 — Vendor-Recommended** | Manufacturer security guide followed; vendor security features enabled; all firmware updates applied | Measure vendor-provided improvement |
| **3 — Best-Practice** | NIST SP 800-213 + ETSI EN 303 645 + OWASP IoT Top 10 applied: segmentation (isolated IoT VLAN), unnecessary services disabled, strong generated credentials (20+ char), certificate pinning where possible, DNS filtering of analytics | Measure maximum achievable security with consumer tools |

---

## D. Attack matrix

### Network vectors

| Attack | Tool(s) | Target protocols | Success criterion | Defense tested |
|--------|---------|------------------|-------------------|----------------|
| MITM — ARP spoofing | bettercap | HTTP, RTSP, cloud TLS | Capture plaintext credentials or data stream | HTTPS enforcement, cert validation |
| MITM — Evil Twin | WiFi Pineapple | WiFi (WPA2/WPA3) | Device connects to rogue AP | SSID validation, WPA3 |
| TLS interception | Pineapple / sslsplit | HTTPS, TLS | Intercept and decrypt traffic | Certificate pinning, proper validation |
| Credential attack | hydra / ffprobe (protocol-correct client) | RTSP, HTTP, SSH, Telnet | Unauthorized access via defaults or brute force | Strong passwords, lockout |
| Deauthentication | aireplay-ng, Flipper Zero | 802.11 | Force disconnect, capture handshake | WPA3, 802.11w |
| Port scanning | nmap | All TCP/UDP | Enumerate open services | Firewall, minimal services |
| Service exploitation | Metasploit / manual | Device-specific | Code exec, crash, or elevated access | Firmware updates, hardening |

### RF / wireless vectors

| Attack | Tool(s) | Frequency / protocol | Success criterion | Defense tested |
|--------|---------|----------------------|-------------------|----------------|
| Sub-GHz capture/replay | Flipper Zero | 315/433/868/915 MHz | Replay triggers device action | Rolling codes, encryption |
| Sub-GHz jamming | Flipper Zero | 315/433 MHz | Disrupt operation >30 s | Fail-safe behavior |
| BLE proximity | Flipper Zero (ESP32) | Bluetooth LE | Connect beyond range or without pairing | Proximity enforcement, secure pairing |
| BLE sniffing | Flipper Zero, btmon | Bluetooth LE | Capture and decode BLE traffic | Encryption, key exchange |
| RFID/NFC cloning | Flipper Zero | 125 kHz, 13.56 MHz | Clone access credential | Unique tokens, challenge-response |
| Zigbee capture | HackRF One | 2.4 GHz (ch 11–26) | Intercept Zigbee traffic | Non-default keys, encryption |

---

## E. Per-device phase workflows

Each device follows a five-phase sequence. Phases are the unit of comparison across states; the schedule below defines which phases repeat in States 2 and 3.

### IP camera

1. **Reconnaissance (passive)** — network discovery, 24-hour traffic baseline
2. **Credential attack** — default-credential test, then brute force if defaults fail
3. **MITM** — ARP-spoof setup, stream/cloud interception
4. **Privacy analysis** — cloud-communication analysis, tracking-domain enumeration
5. **Firmware/hardware** — firmware extraction (vendor image or UART), static analysis

Schedule: State 1 all phases; States 2 and 3 re-run Phases 2–4 (and Phase 5 re-checked if an update shipped new firmware).

### Smart TV

1. **Baseline data collection** — 48-hour normal-usage monitoring
2. **Evil Twin** — Pineapple config, forced connection, analysis
3. **Application security** — app auth testing, update-mechanism analysis
4. **UPnP/DLNA** — protocol fuzzing
5. **Privacy quantification** — data-exfiltration measurement, DNS-filtering test

Schedule: State 1 all phases; States 2 and 3 re-run Phases 2, 3, 5 (State 3 with segmentation).

### Smart lock

1. **Signal reconnaissance** — frequency identification, normal-operation capture
2. **Replay** — signal replay test, variation analysis
3. **BLE testing** — pairing security, packet sniffing
4. **Jamming / DoS** — RF jamming, fail-safe behavior
5. **Physical security** — hardware-interface access

Schedule: State 1 all phases; State 2 Phases 2–4 if vendor exposes security settings; State 3 limited (hardware-level security).

---

## F. Logging and documentation

Every finding is recorded with the tool and exact command that produced it, cross-checked by an independent parser where feasible, and stored as a dated evidence file.

**Test log fields:** Test ID · Date/Time · Device · State · Attack vector · Procedure · Result · Observations · Evidence reference · Vulnerability score · Next steps.

**Evidence-handling discipline:** a tooling choice can change a result's correctness (observed directly in this study — see findings summary), so the authoritative tool for each protocol is recorded and reused across states. Hypotheses that are raised and later disproven are preserved in the record, not deleted, so dead ends are not rediscovered. Generality claims that a single unit cannot support are stated as limitations rather than asserted.

---

## G. Success / failure criteria

**Attack success.** Network: MITM intercepts *and* decrypts/captures credentials or sensitive data; credential attack gains admin access; deauth forces disconnect *and* captures auth material; service exploitation executes code, crashes a service, or elevates access. RF: replay triggers a device action; jamming disrupts operation >30 s; BLE sniffing captures and decodes traffic.

**Mitigation outcome (States 2/3), per attack:**
- **Prevented** — no sensitive data captured in a one-hour window, no unauthorized access, device operates normally, auth attempts logged.
- **Partially mitigated** — difficulty materially increased (≈10× time), limited non-critical exposure, or detection/logging occurs.
- **Failed to mitigate** — attack succeeds with similar ease, or a different vector achieves the same goal.

Cross-state metrics: attack success rate per state, absolute and relative risk reduction, and effectiveness by category (credential / network / RF), used to separate high-impact from placebo mitigations.

---

## H. Ethics, legal, and oversight

Testing is confined to researcher-owned devices on the controlled network described in Section A, consistent with the CFAA (18 U.S.C. § 1030), FCC Part 15 (47 CFR), and the Wiretap Act (18 U.S.C. § 2511). RF testing stays within Part 15 power limits, with replay and jamming confined to a Faraday bag and neighbors notified of RF activity. The Pineapple is restricted to the test SSID with MAC filtering and is disabled between tests; no AP mimicking a legitimate network is created, and no non-test traffic is captured.

**Human-subjects determination:** assessed with institutional Worksheet 301 and determined **not** human-subjects research (no interaction with or data about living individuals; only researcher-owned devices). No eProtocol submission required; advisor concurrence on file.

**Coordinated disclosure:** findings not already in the CVE database or literature are handled under coordinated vulnerability disclosure consistent with CERT/CC guidance — vendor contact, a full technical report starting a 90-day window, and publication held until the window closes or a fix ships. Already-documented issues are referenced directly. Pre-publication, all MAC/IP addresses, credentials, serials, and identifying data in evidence are replaced with placeholders; captures are sanitized. See `disclosure-status.md`.
