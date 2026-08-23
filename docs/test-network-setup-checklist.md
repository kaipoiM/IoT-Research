# Test Network Setup Checklist

Use this to stand up and verify the isolated test network before any device testing begins. This turns the specifications in `docs/legal-ethics.md` and `tools/configs/wifi_pineapple.md` into a concrete, checkable setup process.

---

## 1. Physical Network Isolation

**Status check: which network are you using right now?**
- [ ] **Interim:** Archer AX4400 Guest Network — see `docs/interim-network-archer-ax4400.md` for full setup and required caveats
- [ ] **Target:** Raspberry Pi 3B+ dedicated router — see `tools/configs/raspberry_pi_router.md` (currently blocked on SD card compatibility issue as of this writing; switch to this once resolved)

Complete the sub-checklist in whichever document applies to your current session, then return here.

- [ ] Confirmed which network is active for this session, and this is recorded in the session's test log metadata (important for methodology transparency — see interim doc's transition plan)
- [ ] No bridging/routing exists between the test network and any other network — verified via the ping test below

**Verification test (mandatory before every session, especially critical if using the interim guest-network setup):**

```bash
# Run from Kali laptop connected to IoTSecTest:
ping -c 4 8.8.8.8
# Expected result: 100% packet loss / no route to host
```

If this succeeds, **stop testing immediately** — isolation is not correctly configured. Do not proceed until this is fixed.

---

## 2. Access Control

- [ ] MAC address filtering enabled via hostapd `macaddr_acl=1` and `/etc/hostapd/allowed_macs` (see `tools/configs/raspberry_pi_router.md`)
- [ ] SSID broadcast disabled except during active test windows (`ignore_broadcast_ssid` toggled in hostapd config, or simply stop the hostapd service between sessions)
- [ ] WPA2 passphrase set (see hostapd config — do not commit the actual passphrase to the repo)
- [ ] Document each device's MAC address as it's added to the allowlist:

| Device | MAC Address | Date Added |
|--------|-------------|------------|
| Aqara 2K Camera | | |
| LG 43UK6550PUB TV | | |
| KUCACCI Smart Lock (if it has any WiFi gateway component) | | |
| Kali Linux laptop | | |
| Management/logging server | | |

---

## 3. Equipment Connectivity Check

- [ ] Kali Linux laptop connects to `IoTSecTest`, has working packet capture (`tcpdump -i <iface> -c 5` shows traffic)
- [ ] WiFi Pineapple powered on, accessible via its management interface, **not yet** broadcasting PineAP (per `docs/legal-ethics.md` — only enabled during active Phase 2/Evil Twin tests)
- [ ] Flipper Zero (Momentum) powered on, SD card readable, ESP32 module responds to BLE scan test
- [ ] HackRF One recognized by host: `hackrf_info` returns valid device info (no errors)
- [ ] Management/logging server reachable and has adequate storage for pcap/RF capture files

---

## 4. Legal/Ethics Cross-Check

Before any live testing, confirm the physical setup actually matches what's documented in `docs/legal-ethics.md`:

- [ ] Faraday bag/cage available and tested (put a phone inside, confirm it loses signal) — required before any RF jamming or replay tests
- [ ] Test location confirmed to have reasonable distance from neighboring units, per FCC Part 15 compliance discussion
- [ ] Neighbor notification completed (if applicable to your living situation) — date: _______
- [ ] `docs/legal-ethics.md` Section B (RF compliance) and Section C (WiFi Pineapple restrictions) re-read immediately before first live test session

---

## 5. Baseline "Day Zero" Documentation (Do This Before Touching Any Device)

For each of the three devices, before any testing begins:

| Field | Aqara Camera | LG TV | KUCACCI Lock |
|-------|-------------|-------|--------------|
| Serial number | | | |
| Firmware / webOS / app version at unboxing | | | |
| MAC address (if WiFi-capable) | | | |
| Purchase date / receipt on file | | | |
| Photos taken (unboxed, physical ports/labels) | | | |

**Critical for LG TV specifically:** record the webOS build number *before* any "Check for Update" is triggered — this determines whether CVE-2023-6317 testing happens against a patched or unpatched baseline. See `experiments/smart-tv/README.md`.

---

## 6. Sign-off

- [ ] All sections above completed and verified
- [ ] Ready to begin Phase 1 (Reconnaissance) per each device's `experiments/<device>/README.md`

Date network setup completed: _______________
Verified by: _______________________
