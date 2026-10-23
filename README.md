# Consumer IoT Security: A Three-State Comparative Assessment

An independent security research study evaluating whether manufacturer-recommended and best-practice hardening meaningfully reduce the attack surface of current-generation (2026) consumer IoT devices, measured by testing each device in three configuration states against an identical attack sequence.

> **Disclosure status.** This project involves active security findings against commercial devices. Full technical detail for unpatched findings is withheld under **coordinated vulnerability disclosure** until the applicable 90-day windows close or vendor fixes ship. This public repository contains the methodology, tooling, standards alignment, and findings *summaries* (severity and category). Reproduction detail, evidence files, and raw captures are held privately until disclosure windows close. See [`docs/disclosure-status.md`](docs/disclosure-status.md).

---

## Research question

Do the security improvements promised by vendor hardening guides and by published best-practice frameworks (NIST SP 800-213, ETSI EN 303 645, OWASP IoT Top 10) actually hold up against documented attack patterns? Or do root causes that sit *below* the configurable layer — in firmware, bootloader, and hardware interfaces — persist regardless of how carefully a user hardens the device?

The hypothesis under test: **configuration-level hardening cannot remediate vulnerabilities whose root cause is below the OS and network layer**, and a rigorous comparison across three states will make that gap measurable rather than assumed.

## Method

Each device is tested in three states, with an identical five-phase attack sequence applied to each state so results are directly comparable:

| State | Definition |
|-------|-----------|
| **1 — Factory Default** | Out-of-box, unchanged credentials, all features enabled |
| **2 — Vendor-Recommended** | Manufacturer security guide followed, firmware updated |
| **3 — Best-Practice** | NIST SP 800-213 + ETSI EN 303 645 + OWASP IoT Top 10 applied |

**Five phases per state:** (1) configuration/port baseline, (2) credential testing, (3) MITM / TLS interception, (4) traffic analysis, (5) firmware/hardware analysis.

Full methodology: [`docs/methodology.md`](docs/methodology.md). Scoring rubric: [`docs/vulnerability-scoring.md`](docs/vulnerability-scoring.md).

## Devices under test

| Device | Category | Primary attack surface |
|--------|----------|------------------------|
| Aqara G100 Indoor/Outdoor Camera | Surveillance | Network, TLS, RTSP, firmware, UART |
| LG 43UK6550PUB Smart TV (webOS) | Consumer electronics | Traffic analysis, TLS, application layer |
| KUCACCI Smart Door Lock | Physical security | BLE, sub-GHz RF, RFID |

All devices are researcher-owned. All testing is conducted on an isolated/controlled test network under a documented legal and ethical framework ([`docs/legal-ethics.md`](docs/legal-ethics.md)) and an IRB determination of *not human-subjects research* ([`docs/irb-determination.md`](docs/irb-determination.md)).

## Status

| Device | S1 | S2 | S3 |
|--------|----|----|----|
| Aqara G100 camera | ✅ complete | ⏳ pending | ⏳ pending |
| LG smart TV | ⏳ | ⏳ | ⏳ |
| KUCACCI lock | ⏳ | ⏳ | ⏳ |

Current findings summary (severity and category, detail embargoed): [`docs/findings-summary.md`](docs/findings-summary.md).

## What this repository demonstrates

- A reproducible, standards-aligned testing methodology applied consistently across devices and configuration states
- Disciplined evidence handling: every finding recorded with the tool and command that produced it, cross-checked where possible by independent parsers
- Intellectual honesty as a first-class practice — negative results, retracted hypotheses, and tooling choices that changed a finding's correctness are all preserved in the record, not discarded
- Coordinated vulnerability disclosure handled to professional standard, including self-reported prior exposure

## Repository layout

```
docs/          methodology, scoring, standards, legal/ethics, IRB, disclosure status, findings summary
scripts/       network and RF tooling (device-agnostic)
experiments/   per-device test plans (evidence held privately during embargo)
tools/configs/ test-equipment configuration references
```

## Standards alignment

NIST SP 800-213 · ETSI EN 303 645 · OWASP IoT Top 10 · California SB-327

## Author

[Your name] — [program / institution, optional]
Contact: [email]

## License

Research and documentation: CC BY 4.0 · Scripts: MIT

> All testing was conducted on researcher-owned devices in a controlled environment in compliance with 18 U.S.C. § 1030 (CFAA), 47 CFR Part 15 (FCC), and 18 U.S.C. § 2511 (Wiretap Act).
