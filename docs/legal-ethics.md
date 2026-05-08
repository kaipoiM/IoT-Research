# Legal & Ethical Compliance Framework

## Overview

All IoT security testing in this research is conducted under strict legal and ethical constraints. This document defines the compliance framework for testing activities involving penetration testing, protocol analysis, and RF signal testing.

---

## Test Environment Controls

### Isolated Network Architecture

```
[ Kali Linux Laptop ] ──── [ Dedicated Router ] ──── [ IoT Devices ]
         │                    SSID: IoTSecTest              │
         │                    No internet uplink            │
[ Management Server ] ──── [ WiFi Pineapple ]         (air-gapped)
```

- **Dedicated router** with no internet connection
- **SSID:** `IoTSecTest` — prevents confusion with production networks
- **MAC address filtering** restricts network to authorized research equipment only
- **Physical isolation:** Test bench separated from production networks
- All devices purchased for this research — receipts retained as legal documentation of ownership

---

## Legal Compliance

### Computer Fraud and Abuse Act (18 U.S.C. § 1030)

**Compliance:** All testing is performed on devices owned by the researcher, on an isolated network with no connection to third-party systems.

**Controls:**
- No testing on devices owned by others
- No access to third-party networks or cloud services beyond expected device communication
- Device cloud accounts use researcher-created accounts only
- Receipts document ownership for all test devices

### FCC Regulations (47 CFR Part 15)

**Compliance:** All RF transmissions remain within unlicensed band power limits. No interference with licensed radio services.

**RF Transmission Controls:**

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

---

## Ethical Safeguards

### Wi-Fi Pineapple Restrictions

- SSID: `IoTSecTest` only — never impersonating legitimate networks
- MAC address whitelist: only test devices may connect
- Broadcast disabled when not actively testing
- Physical placement restricted to test area
- **Prohibited:** Creating APs mimicking legitimate networks, capturing non-test device traffic

### Data Sanitization

Before any publication:

| Data Type | Sanitization Action |
|-----------|---------------------|
| MAC addresses | Replace with `XX:XX:XX:XX:XX:XX` placeholders |
| IP addresses | Replace with `192.168.100.X` generic placeholders |
| Device serial numbers | Redacted |
| Account credentials | Referenced generically (e.g., "weak default password") |
| Packet captures | PII stripped using `tcpdump -r in.pcap -w out.pcap 'not host [personal_ip]'` |
| Screenshots | Sanitized to remove identifying information |

### Coordinated Vulnerability Disclosure

For **newly discovered vulnerabilities** not documented in CVE/NVD or academic literature:

1. Prepare disclosure report using `templates/vuln-report.md`
2. Notify vendor via their security contact (check `security.txt` at vendor domain)
3. Allow 90 days for patch development
4. Escalate to CERT/CC if no response within 30 days
5. Public disclosure at 90 days regardless of patch status

Disclosure includes: vulnerability description, affected versions, sanitized proof of concept, CVSS score, remediation recommendation.

**Already-documented vulnerabilities** (CVE database, prior academic literature) may be referenced directly without separate disclosure.

### Institutional Review Board (IRB)

> **TODO:** Determine whether IRB review is required for this research.
>
> **Guidance:** IoT security testing on owned devices in an isolated environment typically falls under security research exemptions and does not involve human subjects data. However, if research involves:
> - Collection of any personal data from human participants
> - Questionnaires or surveys of users
> - Analysis of data that could be linked to individuals
>
> ...then IRB review may be required. Consult your institution's IRB office.
>
> **Relevant precedent:** Prior IoT security research (Mirai analysis, SmartThings security analysis) was conducted without IRB review when limited to owned devices and published attack pattern reproduction.

---

## Scope Boundaries

| In Scope | Out of Scope |
|----------|-------------|
| Devices purchased for this research | Any device not owned by researcher |
| Isolated test network (SSID: IoTSecTest) | Production networks or internet |
| Known, documented attack patterns | Zero-day exploit development |
| Passive traffic analysis | Active interference with services |
| Standard penetration testing tools | Custom malware or destructive payloads |
| RF testing within FCC Part 15 | Licensed frequency interference |

---

*Last reviewed: 2026 | Compliance with: 18 U.S.C. § 1030, 47 CFR Part 15, 18 U.S.C. § 2511*
