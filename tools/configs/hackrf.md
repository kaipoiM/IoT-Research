# HackRF One — Configuration & Calibration Notes

## Device Info

| Field | Value |
|-------|-------|
| **Firmware version** | _fill in — `hackrf_info` reports this_ |
| **Serial number** | _fill in — `hackrf_info` reports this_ |
| **Purchase/acquisition date** | _fill in_ |
| **Antenna(s) used** | _fill in — stock antenna, or upgraded (e.g., ANT500)_ |

Run `hackrf_info` and paste full output here for the record:
```
$ hackrf_info

```

---

## Software Environment

| Tool | Version | Install command |
|------|---------|------------------|
| `hackrf` (host tools) | _fill in `hackrf_info --version` or `dpkg -l hackrf`_ | `apt install hackrf` |
| GNU Radio | _fill in `gnuradio-config-info --version`_ | `apt install gnuradio` |
| gr-ieee802-15-4 (Zigbee OOT module) | _fill in_ | build from source — see notes below |
| Wireshark | _fill in `wireshark --version`_ | `apt install wireshark` |

### gr-ieee802-15-4 build notes
_Document any build issues/fixes here once installed — this module is not in standard apt repos on most Kali/Ubuntu versions and typically requires building from source against your GNU Radio version._

```
# Example build steps (fill in actual working steps):
git clone https://github.com/bastibl/gr-ieee802-15-4.git
cd gr-ieee802-15-4
mkdir build && cd build
cmake ..
make
sudo make install
sudo ldconfig
```

**If build fails / unreliable capture:** fall back to nRF52840 dongle + Wireshark sniffer firmware for Zigbee capture (noted as the recommended primary path in `scripts/rf/zigbee_sniff.sh`).

---

## Calibration & Known-Good Settings

### General TX/RX parameters
| Parameter | Value | Notes |
|-----------|-------|-------|
| Sample rate (RX, general) | _fill in, e.g. 8 MHz_ | |
| Sample rate (Zigbee/O-QPSK) | 4 MHz minimum | Required for 2 Mchip/s O-QPSK demod |
| LNA gain | _fill in, e.g. 24-32_ | Range 0-40, 8dB steps |
| VGA gain | _fill in, e.g. 20-40_ | Range 0-62, 2dB steps |
| TX gain (jamming/replay tests only) | _fill in — use MINIMUM effective power_ | Range 0-47, 1dB steps |
| Amp enable (RX) | _fill in on/off_ | +14dB, use only if signal weak |

### Zigbee channel-to-frequency reference
Zigbee channels 11–26 map to 2.4 GHz per: `freq_MHz = 2405 + 5 × (channel − 11)`

| Channel | Frequency (MHz) | Channel | Frequency (MHz) |
|---------|------------------|---------|------------------|
| 11 | 2405 | 19 | 2445 |
| 12 | 2410 | 20 | 2450 |
| 13 | 2415 | 21 | 2455 |
| 14 | 2420 | 22 | 2460 |
| 15 | 2425 | 23 | 2465 |
| 16 | 2430 | 24 | 2470 |
| 17 | 2435 | 25 | 2475 |
| 18 | 2440 | 26 | 2480 |

_Once devices are confirmed, record which channel each Zigbee-capable device actually uses:_
- Device: _______ → Channel: _______

### Frequency accuracy check
HackRF One's onboard oscillator has some drift. If precise frequency work is needed (e.g., distinguishing adjacent Zigbee channels cleanly):
```
hackrf_debug --si5351c -R    # read clock generator config
```
_Record any observed drift/offset here after testing against a known reference signal._

---

## Shielding & RF Safety Setup

| Item | Status |
|------|--------|
| Faraday bag model/spec | _fill in_ |
| Faraday bag verified attenuation | _fill in if measured, or note "manufacturer spec only"_ |
| Test location | _fill in — confirm distance from neighbors per docs/legal-ethics.md_ |
| Neighbor notification completed | _fill in date_ |

---

## Known Issues / Troubleshooting Log

_Add entries as you encounter and resolve issues during setup and testing._

| Date | Issue | Resolution |
|------|-------|------------|
| | | |
