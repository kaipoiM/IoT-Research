# Legal & Ethical Compliance Framework

## Overview

All IoT security testing in this research is conducted under strict legal and ethical constraints. This document defines the compliance framework for testing activities involving penetration testing, protocol analysis, and RF signal testing.

---

## Test Environment Controls

The test network provides **LAN isolation from the household in all configurations**. Two topologies are used, selected per device according to whether the device can operate without cloud connectivity. The topology used for each device, and the reason, is recorded in that device's experiment file.

### Topology A — Fully isolated (no internet)

Used for devices that function without cloud connectivity, and for all RF-only testing.

```
[ Parrot OS Laptop ] ──── [ Raspberry Pi 4B AP ] ──── [ IoT Devices ]
         │                   SSID: IoTSecTest                │
         │                   No WAN uplink                    │
[ WiFi Pineapple ]  ────────┘                          (air-gapped)
```

- Raspberry Pi 4B runs the AP (hostapd + dnsmasq) with **no internet uplink**
- eth0 is used for SSH administration only and is not bridged or routed to the AP interface
- Verified before every session: a connected client pinging an external host returns **100% packet loss**. If that ping ever succeeds, testing stops until isolation is restored.

### Topology B — Controlled-internet (cloud-dependent devices)

Some devices under test (notably the Aqara G100 camera) are **cloud-dependent and cannot be provisioned or operated offline** — initial setup and normal operation require reaching the vendor cloud. For these, full isolation is impossible, so a controlled path is used:

```
[ IoT Device ] [ Parrot OS Laptop ] [ setup phone ]
        │
   WiFi Pineapple AP (SSID: IoTSecTest)
        │
   Router guest network (client isolation ON, no access to household LAN)
        │
   Internet ──── vendor cloud
```

- The WiFi Pineapple is the controlled MITM position between the device and its cloud.
- The router **guest network** provides client isolation from the household LAN; test devices cannot reach household systems.
- Internet access is scoped to the device's own expected cloud communication — the only traffic leaving the segment is the device talking to its vendor, which is the behavior under study.
- This path is used **only** where a device's cloud dependency makes Topology A impossible, and the necessity is documented per device.

### Common controls (both topologies)

- **SSID** `IoTSecTest` — prevents confusion with production networks
- **MAC address filtering** restricts the network to authorized research equipment only
- **Physical isolation:** test bench separated from production networks
- All devices purchased for this research — receipts retained as documentation of ownership

---

## Legal Compliance

### Computer Fraud and Abuse Act (18 U.S.C. § 1030)

**Compliance:** All testing is performed on devices owned by the researcher. Network access is limited to the controlled test network; the only third-party system contacted is the vendor cloud belonging to the device under test, via researcher-created accounts, as part of that device's normal expected operation.

**Controls:**
- No testing on devices owned by others
- No access to third-party networks or cloud services beyond the test device's own expected vendor communication
- Device cloud accounts use researcher-created accounts only
- Receipts document ownership for all test devices

### FCC Regulations (47 CFR Part 15)

**Compliance:** All RF transmissions remain within unlicensed band power limits. No interference with licensed radio services.

| Tool | Frequency | Power Limit | Shielding |
|------|-----------|-------------|-----------|
| Flipper Zero | 315/433/868/915 MHz | Part 15.249 PSD limit | Faraday bag for replay/jamming |
| HackRF One | 2.4 GHz (ZigBee Ch 11-26) | Minimized to functional level | Shielded enclosure |
| WiFi Pineapple | 2.4/5 GHz | Part 15.247 | Test area only |

**Prohibited actions:**
- No jamming or interference with licensed services (cellular, emergency, aviation)
- No transmission on restricted frequencies
- No RF emissions that could interfere with neighboring wireless devices
- Sensitive tests (replay, jamming) conducted inside Faraday bag/cage

**Neighbor notification:** Adjacent residents notified of RF research activities with contact information for interference concerns.

### Wiretap Act (18 U.S.C. § 2511)

**Compliance:** All network interception is limited to owned devices on the test network.

**Controls:**
- WiFi Pineapple SSID restricted to test devices only
- MAC address filtering ensures only test devices connect
- No capturing traffic from non-test devices
- Rogue AP disabled immediately after test completion
- No operating outside the controlled test environment
- Interception of the device-to-cloud path (Topology B) covers only the researcher's own device and account

---

## Ethical Safeguards

### Wi-Fi Pineapple Restrictions

- SSID: `IoTSecTest` only — never impersonating legitimate networks
- MAC address allow-list: only test devices may connect
- PineAP and Karma disabled; broadcast disabled when not actively testing
- Physical placement restricted to test area
- **Prohibited:** creating APs mimicking legitimate networks, capturing non-test device traffic

### Data Sanitization

Before any publication, evidence is sanitized to documentation-reserved ranges:

| Data Type | Sanitization Action |
|-----------|---------------------|
| IP addresses | Replace with `192.0.2.x` (RFC 5737 TEST-NET-1) |
| MAC addresses | Replace with `00:00:5E:00:53:xx` (RFC 7042 documentation range) |
| Device serial numbers | Redacted |
| Account credentials | Referenced generically (e.g., "weak default password"); never the real value |
| Signed cloud URLs / tokens | Replaced with `[REDACTED-SIGNED-URL]` |
| Local filesystem paths | Replaced with `/path/` |
| Packet captures | A text scrub does not clean a `.pcap`; captures are re-captured sanitized or omitted, not committed raw |
| Screenshots | Sanitized to remove identifying information |

### Coordinated Vulnerability Disclosure

For **newly discovered vulnerabilities** not documented in CVE/NVD or academic literature:

1. Prepare disclosure report
2. Notify vendor via their security contact (check `security.txt` at vendor domain; the parent entity may be the real destination)
3. Send a full technical report — **this starts a 90-day window**, extendable by mutual agreement if a fix needs more time
4. Escalate to CERT/CC if no vendor response within 30 days
5. Public disclosure at 90 days or vendor fix, whichever comes first

Disclosure includes: vulnerability description, affected versions, sanitized proof of concept, CVSS score, remediation recommendation. Any inadvertent prior public exposure is reported to the vendor as part of initial contact. **Already-documented vulnerabilities** (CVE database, prior literature) may be referenced directly without separate disclosure. Status tracked in `disclosure-status.md`.

### Institutional Review Board (IRB)

**Determination: not human-subjects research.** Assessed using the institution's Worksheet 301 ("Is my project human-subjects research?"). The research involves no interaction or intervention with living individuals and collects no identifiable private information about any person — testing is confined to researcher-owned devices and their own vendor-cloud traffic on the researcher's own accounts. The determination is therefore that this is not human-subjects research, no eProtocol/IRB submission is required, and advisor concurrence is on file.

This is consistent with precedent for IoT security research (e.g. Mirai analysis, SmartThings security analysis) conducted without IRB review when limited to owned devices and attack-pattern reproduction. Should scope ever expand to collecting data from human participants (surveys, user studies, or analysis of data linkable to individuals), an IRB determination would be re-sought before that work begins.

---

## Scope Boundaries

| In Scope | Out of Scope |
|----------|-------------|
| Devices purchased for this research | Any device not owned by researcher |
| Controlled test network (SSID: IoTSecTest) | Production networks; general internet use |
| Test device's own vendor-cloud traffic (researcher accounts) | Any third-party system or account |
| Known, documented attack patterns | Zero-day exploit development for offensive use |
| Passive traffic analysis | Active interference with live services |
| Standard penetration testing tools | Custom malware or destructive payloads |
| RF testing within FCC Part 15 | Licensed frequency interference |

---

*Last reviewed: October 2026 | Compliance with: 18 U.S.C. § 1030, 47 CFR Part 15, 18 U.S.C. § 2511*
