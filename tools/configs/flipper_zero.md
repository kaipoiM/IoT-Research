# Flipper Zero — Configuration Notes (Momentum Firmware)

## Device Info

| Field | Value |
|-------|-------|
| **Firmware** | Momentum — _fill in exact version, e.g. MMomentum 010.x_ |
| **Firmware source** | https://github.com/Next-Flip/Momentum-Firmware |
| **Flash date** | _fill in_ |
| **Serial number** | _fill in — Settings > About_ |
| **ESP32 WiFi/BLE module installed** | Yes — _fill in module/firmware version_ |

**Note for methodology write-up:** Momentum is a community fork of the official firmware, not Flipper Devices' stock firmware. Document this explicitly in your methodology section — some protocol support, regional frequency restrictions, and default behaviors differ from stock, which matters for reproducibility if someone tries to replicate your testing on stock firmware.

---

## Why Momentum (vs. stock)

_Fill in your actual reasoning, e.g.:_
- Expanded Sub-GHz protocol database (More de Bruijn/bruteforce support for fixed-code garage/gate remotes)
- Region lock removed/configurable for RF frequency testing within legal limits (confirm this doesn't put you outside FCC Part 15 — region unlock affects TX permissions, not the underlying legal requirement)
- Additional BLE/GATT tooling improvements over stock

**Important:** Region/frequency unlocking in custom firmware does NOT change your legal obligations under FCC Part 15. Document in `docs/legal-ethics.md` cross-reference that all testing remains within Part 15.249 limits regardless of what the firmware allows the hardware to attempt.

---

## Module & App Configuration

### Sub-GHz Settings
| Setting | Value | Notes |
|---------|-------|-------|
| Region setting | _fill in_ | Verify against actual legal TX limits, not just firmware capability |
| Default frequency (testing) | 433.92 MHz | Adjust per device under test |
| Modulation presets used | _fill in — AM650 (OOK), FM238 (2FSK), etc._ | |
| Custom frequency list edited? | _fill in yes/no_ | If yes, note file: `subghz/assets/setting_user.txt` |

### BLE/ESP32 Module
| Setting | Value |
|---------|-------|
| ESP32 firmware version | _fill in_ |
| BLE scan mode used | _fill in — passive/active_ |
| Marauder-style firmware installed? | _fill in yes/no — Momentum has its own WiFi dev board apps; confirm what's actually flashed_ |

### RFID/NFC
| Setting | Value |
|---------|-------|
| 125kHz support confirmed | _fill in_ |
| 13.56MHz (NFC) support confirmed | _fill in_ |
| Relevant for | KUCACCI lock RFID fob testing (if fob access method enabled) |

---

## SD Card / File Organization

Recommended structure for research capture files (adjust to match actual Flipper SD layout):

```
subghz/
  captures/
    lock_kucacci_s1_<date>/
    tv_lg_s1_<date>/         # if TV has any RF surface beyond WiFi
nfc/
  captures/
    lock_kucacci_fob_<date>/
```

Transfer captures to `scripts/rf/` output directories (see `subghz_capture.sh` `--out` flag) via qFlipper or SD card removal after each test session — don't leave research captures only on-device.

---

## Known Issues / Troubleshooting Log

_Add entries as you encounter and resolve issues during setup and testing._

| Date | Issue | Resolution |
|------|-------|------------|
| | | |

---

## Reproducibility Note for Methodology Section

When writing up equipment configuration in your methodology, include:
1. Exact Momentum firmware version and commit/release tag
2. Any deviations from default Momentum settings (custom frequency lists, modified regional settings)
3. ESP32 module firmware version separately from main Flipper firmware
4. Explicit statement that RF testing remained within FCC Part 15 limits regardless of firmware-level region settings
