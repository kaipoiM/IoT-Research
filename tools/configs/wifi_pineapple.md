# WiFi Pineapple — Configuration Notes

## Device Info

| Field | Value |
|-------|-------|
| **Model** | _fill in — Mark VII / Mark VII Basic / other_ |
| **Firmware version** | _fill in — check Pineapple web UI, System > Firmware_ |
| **Acquisition date** | _fill in_ |

---

## Test Network Configuration

**This section documents the live implementation of the restrictions specified in `docs/legal-ethics.md` Section C. If any value here diverges from that doc, update both.**

| Setting | Value |
|---------|-------|
| Test SSID | `IoTSecTest` |
| SSID broadcast | Disabled except during active test windows |
| MAC address filtering | Enabled — allowlist only |
| Allowlisted MAC(s) | _fill in — MAC of each device under test, added/removed as needed_ |
| WPA2/WPA3 mode (legit test network, non-evil-twin tests) | _fill in_ |
| Physical placement | _fill in location — confirm signal containment to test area_ |
| Internet uplink | Disabled during active testing |

---

## PineAP / Evil Twin Module Settings

| Setting | Value |
|---------|-------|
| PineAP module enabled | Only during Phase 2 (Evil Twin) tests, disabled otherwise |
| Broadcast SSID pool | Restricted to `IoTSecTest` only — **do not** enable broadcast of harvested/probed SSIDs from surrounding environment (would constitute testing against non-consented networks) |
| Karma mode | Disabled — Karma responds to any probing client, which risks capturing non-test devices |
| Client deauth targeting | Restricted to allowlisted test device MAC(s) only |

**Reminder from `docs/legal-ethics.md`:** the rogue AP must be the only network the test device has credentials for, and must be disabled immediately after each test completes.

---

## SSLsplit / Interception Module

| Setting | Value |
|---------|-------|
| SSLsplit module version | _fill in_ |
| Used standalone or via `scripts/network/mitm_arp.sh`? | _fill in — mitm_arp.sh runs its own SSLsplit instance on the Kali laptop; clarify whether Pineapple's built-in module is used instead/additionally for any tests_ |

---

## Logging

| Setting | Value |
|---------|-------|
| PineAP log retention | _fill in_ |
| Log export method | _fill in — SCP, web UI download, etc._ |
| Log storage location (on research machine) | Match `experiments/<device>/logs/` convention; sanitize MACs/SSIDs of any non-test devices before including in any published log per `docs/legal-ethics.md` Section D |

---

## Known Issues / Troubleshooting Log

_Add entries as you encounter and resolve issues during setup and testing._

| Date | Issue | Resolution |
|------|-------|------------|
| | | |
