# Standards Summary

The three frameworks this study uses to define State-3 ("best-practice") hardening and to classify findings. They are complementary: NIST and ETSI define what a secure device *should* do; OWASP provides the vulnerability-centric vocabulary for describing what a device *fails* to do. Findings in this project are tagged against OWASP categories and cross-referenced to the relevant NIST/ETSI provision.

Full citations: `references.md`.

---

## NIST SP 800-213 — IoT Device Cybersecurity Guidance

A risk-based framework for integrating IoT devices into a system by defining each device's **cybersecurity requirements**: the technical capabilities the device must provide, and the non-technical capabilities the manufacturer must support (documentation, update provision, disclosure).

Core idea used here: when a device does not meet an identified requirement, the integrator makes one of four determinations — the gap is justifiably absent; another capability compensates without a control change; another capability compensates but needs a control change; or the gap is unjustifiable with no compensating capability (in which case the device should not be integrated). SP 800-213 names the unsecurable case explicitly — e.g. a device whose default credentials cannot be changed.

**Use in this study:** the risk-based determination model informs State-3 hardening design and frames findings where a device offers no path to meet a requirement at all (the "unsecurable" determination maps directly onto several hardware-layer findings).

---

## ETSI EN 303 645 — Consumer IoT Baseline Requirements

The first internationally recognized baseline specifically for *consumer* IoT, built on security- and privacy-by-design and written as outcome-oriented requirements. It explicitly excludes long-term physical and nation-state threats, targeting the most common vulnerabilities. Adopted as a European Standard in September 2024.

Provisions most relevant to this study:

| Provision | Requirement | Maps to findings about |
|-----------|-------------|------------------------|
| 5.1 | No universal default passwords; unique-per-device or user-defined | Credential strength, SB-327 alignment |
| 5.2 | Coordinated vulnerability disclosure with defined timelines | Vendor response; our own disclosure process |
| 5.3 | Secure, verifiable (signed) update mechanism | Firmware-update signature verification |
| 5.4 | No insecure storage of sensitive security parameters | Key material / credential storage |
| 5.5 | Best-practice cryptography for communication | TLS validation and transport security |
| 5.6 | Unused network and logical interfaces disabled | Attack surface / open services |
| §6 | Disclose what personal data is collected, by whom, for how long; allow deletion | Privacy analysis |

A known limitation the standard states itself: it defines no testing or certification method, and many provisions use non-mandatory "should" language — which creates the gap between stated intent and real conformance that this study measures empirically.

---

## OWASP IoT Top 10

The community-maintained catalog of the most critical IoT vulnerability classes. Used here as the **classification vocabulary** for findings.

| # | Category | Short definition |
|---|----------|------------------|
| I1 | Weak, guessable, or hardcoded passwords | Brute-forceable, public, or unchangeable credentials |
| I2 | Insecure network services | Unneeded/insecure services enabling remote control |
| I3 | Insecure ecosystem interfaces | Weak web/API/cloud/mobile interfaces around the device |
| I4 | Lack of secure update mechanism | No secure/verifiable update path |
| I5 | Use of insecure or outdated components | Deprecated/vulnerable libraries or components |
| I6 | Insufficient privacy protection | Personal data handled insecurely or without consent |
| I7 | Insecure data transfer and storage | Missing encryption/access control at rest, in transit, in use |
| I8 | Lack of device management | No security support for deployed devices |
| I9 | Insecure default settings | Ships insecure; limited ability to harden |
| I10 | Lack of physical hardening | Physical access yields data or local control |

These map onto the ETSI provisions and NIST requirements above, giving each finding a three-way reference: OWASP category (what failed), ETSI/NIST provision (what was required), and CWE where a specific weakness class applies.

---

## California SB-327

First US state IoT security law (effective January 2020). Requires manufacturers selling connected devices in California to equip them with "reasonable security features," specifically either a unique per-device preprogrammed password or a forced user-set password on first access. Used here as the concrete legal baseline against which State-1 default-credential behavior is checked.
