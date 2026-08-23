# IoT Security Research — Consumer Device Vulnerability Assessment (2026)

A hands-on penetration testing study evaluating consumer IoT devices across three security configurations, measuring whether manufacturer-recommended and best-practice hardening provide meaningful protection against documented attack vectors.

---

## Research Overview

**Goal:** Empirically test whether current-generation (2026) consumer IoT devices remain vulnerable to documented attack patterns, and quantify the security improvement provided by vendor-recommended and best-practice hardening.

**Devices Under Test:**

| Device | Category | Primary Attack Surface |
|--------|----------|----------------------|
| Aqara 2K Indoor/Outdoor Security Camera | Surveillance | Network, TLS/cert validation, cloud auth, firmware |
| LG 43UK6550PUB Smart TV | Consumer Electronics | webOS app service (CVE-2023-6317 chain), traffic analysis, SSL/TLS, UPnP/DLNA |
| KUCACCI Smart Door Lock | Physical Security | BLE (TTLock-style app control), keypad, RFID fob |

**Three-State Testing Framework:**
- **State 1 — Factory Default:** Out-of-box, unchanged credentials, all features enabled
- **State 2 — Vendor-Recommended Hardening:** Manufacturer security guide followed, firmware updated
- **State 3 — Best-Practice Hardening:** NIST SP 800-213 + ETSI EN 303 645 + OWASP IoT Top 10 applied

**Standards Alignment:** NIST SP 800-213 · ETSI EN 303 645 · OWASP IoT Top 10 · California SB-327

---

## Repository Structure

```
iot-security-research/
├── README.md
├── docs/
│   ├── methodology.md          # Full three-state testing methodology
│   ├── vulnerability-scoring.md # CVSS-adapted IoT scoring rubric
│   ├── legal-ethics.md         # FCC, CFAA, Wiretap Act compliance
│   └── standards-summary.md    # NIST / ETSI / OWASP reference
├── scripts/
│   ├── network/
│   │   ├── recon.sh            # Passive network discovery & traffic baseline
│   │   ├── mitm_arp.sh         # ARP spoofing + SSL interception setup
│   │   ├── credential_test.sh  # Default credential & brute-force testing
│   │   ├── port_scan.sh        # Nmap service enumeration
│   │   └── deauth_test.sh      # 802.11 deauthentication testing
│   ├── rf/
│   │   ├── ble_scan.sh         # BLE device discovery & pairing analysis
│   │   ├── subghz_capture.sh   # Sub-GHz signal capture workflow
│   │   └── zigbee_sniff.sh     # ZigBee traffic capture via HackRF
│   └── analysis/
│       ├── pcap_parser.py      # Parse captures, flag plaintext credentials
│       ├── tls_checker.py      # Validate TLS config & certificate chain
│       ├── traffic_baseline.py # 24/48-hour traffic profiling & anomaly detection
│       └── score_device.py     # Calculate IoT vulnerability score
├── experiments/
│   ├── ip-camera/
│   │   ├── README.md           # Device-specific test plan
│   │   └── logs/               # Test log entries (JSON)
│   ├── smart-tv/
│   │   ├── README.md
│   │   └── logs/
│   └── smart-lock/
│       ├── README.md
│       └── logs/
├── datasets/
│   ├── pcaps/                  # Sanitized packet captures (PII removed)
│   ├── rf-captures/            # Sub-GHz / BLE signal recordings
│   └── firmware/               # Extracted firmware images & analysis
├── tools/
│   └── configs/
│       ├── wifi-pineapple.md   # Pineapple setup & ethical safeguards
│       ├── flipper-zero.md     # Flipper Zero configuration notes
│       └── hackrf.md           # HackRF One ZigBee analysis setup
└── templates/
    ├── test-log.json           # Standardized test log entry schema
    └── vuln-report.md          # Vulnerability disclosure template
```

---

## Equipment

| Tool | Role | Safety Notes |
|------|------|-------------|
| Kali Linux Laptop | Network attack platform | Isolated test network only |
| Wi-Fi Pineapple | MITM / Rogue AP | SSID `IoTSecTest`, MAC filtering, disabled between tests |
| Flipper Zero + ESP32 | RF protocol testing | Faraday bag for replay/jamming tests |
| HackRF One | ZigBee / Sub-GHz analysis | Shielded environment, FCC Part 15 compliant |
| Management Server | Logging / packet capture | Air-gapped from production network |

---

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/iot-security-research.git
cd iot-security-research

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Run passive network reconnaissance on a device
sudo bash scripts/network/recon.sh --iface eth0 --duration 3600 --out experiments/ip-camera/logs/

# 4. Run TLS validation check
python scripts/analysis/tls_checker.py --target 192.168.100.X --out experiments/ip-camera/logs/

# 5. Test default/weak credentials (network-attached devices only — see notes below)
sudo bash scripts/network/credential_test.sh --target 192.168.100.X --label cam-s1 --out experiments/ip-camera/logs/

# 6. RF testing — Sub-GHz capture/replay/jamming (Flipper Zero, manual-guided workflow)
bash scripts/rf/subghz_capture.sh --label lock-s1 --out experiments/smart-lock/logs/

# 7. RF testing — Zigbee capture (HackRF One, manual-guided workflow)
sudo bash scripts/rf/zigbee_sniff.sh --channel 15 --label device-s1 --out experiments/ip-camera/logs/
```

**Device-specific notes:**
- `credential_test.sh` does not apply to the KUCACCI lock (no network-layer credential surface) — use `scripts/rf/ble_scan.sh` instead.
- The Aqara camera is cloud-account-gated by design; expect closed local admin ports on recon — this is a valid, documentable State 1 finding, not a script failure.
- `subghz_capture.sh` and `zigbee_sniff.sh` are semi-interactive (Flipper Zero and HackRF+GNU Radio lack stable capture CLIs) — they walk you through manual steps and log structured results.

> **⚠️ Legal Notice:** All testing must be performed on devices you own, on an isolated network with no connection to third-party systems. See [`docs/legal-ethics.md`](docs/legal-ethics.md) for full compliance guidance.

---

## Vulnerability Scoring Rubric

Adapted from CVSS with IoT-specific criteria:

| Criterion | Weight | 0 (Worst) → 10 (Best) |
|-----------|--------|----------------------|
| Authentication Strength | 20% | None → Strong MFA |
| Data Encryption | 20% | None → TLS 1.3+ |
| Attack Surface | 15% | Many open services → Minimal exposure |
| Update Mechanism | 15% | None → Signed auto-update |
| Privacy Controls | 15% | No controls → Comprehensive |
| Physical Security | 10% | Debug ports exposed → Tamper-resistant |
| Vendor Response | 5% | No security support → Active program |

**Overall Score = Σ(Criterion × Weight)**

---

## References

Full citations are in [`docs/references.md`](docs/references.md). Key sources:

- Antonakakis et al. (2017) — *Understanding the Mirai Botnet*
- NIST SP 800-213 — *IoT Device Cybersecurity Guidance*
- ETSI EN 303 645 — *Cyber Security for Consumer IoT: Baseline Requirements*
- OWASP IoT Top 10
- Liu et al. (2024) — *Samba: Detecting SSL/TLS API Misuses in IoT Binary Applications*
- Paracha et al. (2021) — *IoTLS: Understanding TLS Usage in Consumer IoT Devices*

---

## License

Research and documentation: [CC BY 4.0](LICENSE)
Scripts: [MIT License](LICENSE-CODE)

> This repository is part of an academic security research project. All testing was conducted on researcher-owned devices in an isolated environment in compliance with 18 U.S.C. § 1030 (CFAA), 47 CFR Part 15 (FCC), and 18 U.S.C. § 2511 (Wiretap Act).
