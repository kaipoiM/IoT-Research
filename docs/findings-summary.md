# Findings Summary

**Public-safe summary.** This page records the *existence, severity, and category* of findings. Reproduction steps, evidence files, affected-value detail, and raw captures are withheld under coordinated disclosure (see [`disclosure-status.md`](disclosure-status.md)) until the applicable window closes or a vendor fix ships. Severity uses the project's IoT-adapted CVSS rubric.

Categories reference the OWASP IoT Top 10 (I1–I10) and CWE where applicable.

---

## Aqara G100 Camera — State 1 (Factory Default), complete

Testing across five phases returned a cluster of findings spanning the network, cryptographic-transport, and hardware/firmware layers. The most severe sit below the OS and network layer — which is the central point the three-state comparison is designed to make: no amount of configuration-level hardening is expected to remediate them.

| Severity | Category | Finding (summary) | Status |
|----------|----------|-------------------|--------|
| CRITICAL | Hardware / auth (CWE-288) | Local hardware-interface path yields unauthenticated administrative access with no credential or integrity check | Embargoed — vendor disclosure |
| CRITICAL | Key management (I6) | Probable exposure of smart-home ecosystem key material via that path | Embargoed |
| CRITICAL | Update integrity (I4, CWE-347) | Firmware-update routine performs no cryptographic signature verification in the examined step | Embargoed |
| CRITICAL | Transport security (CWE-295) | Device TLS client does not validate the cloud server certificate; permits interception of cloud-bound media on a controlled network. Believed distinct in root cause from CVE-2026-50091 (SDK-layer) | Embargoed |
| HIGH | Credentials (I1, CWE-307) | Locally-discoverable stream credential with small keyspace and no rate-limiting / lockout | Embargoed |
| HIGH | Credentials (CWE-258) | Credential field with no value set | Embargoed |
| MEDIUM-HIGH | Key management | Shared constant in factory configuration store, observed identical across two units | Embargoed |
| MEDIUM | Privacy controls (I7) | A user-facing privacy control does not close the network service it implies control over | Documented; vendor-notified |
| MEDIUM | Transport (unresolved) | High-volume peer-to-peer media channel statistically consistent with encryption; cipher and key-exchange not yet verified | Open / under analysis |
| LOW-MEDIUM | Components (CWE-1104) | End-of-life TLS library version present in a current production firmware build | Embargoed |
| LOW | Permissions (CWE-732) | Anomalous permission bits on a non-executable data file | Embargoed |
| INFO (negative) | Credentials | Standard default/weak credential wordlist **correctly rejected** on all exposed local services — device is **not** vulnerable to the generic Mirai-pattern attack | Publishable |

### Methodological notes worth preserving (publishable now)

These are process findings, not device vulnerabilities, and they illustrate the rigor of the method rather than exposing anything embargoed:

- **A tooling choice changed a result's correctness.** An initial RTSP credential probe using one client produced a false-positive "success" because that client misreports the server's auth response; switching to a protocol-correct client returned the true result. The second tool was adopted as authoritative for all subsequent credential testing. A reminder that a finding is only as trustworthy as the instrument that produced it.
- **A hypothesis was raised, tested, and retracted — and kept in the record.** An early theory attributing a pattern in captured traffic to a cryptographic weakness was disproven on inspection (the pattern was an artifact of the capture topology, not device behavior) and is preserved so the dead end is not rediscovered.
- **Two independently-written parsers** cross-checked the Phase 4 traffic figures and agreed on every material value.
- **Two physically separate units** were used where a finding's generality depended on it, and limitations that a single unit could not resolve are stated explicitly rather than glossed.

---

## LG 43UK6550PUB Smart TV

Not yet tested. Record the webOS build string **before** any firmware update.

## KUCACCI Smart Door Lock

Not yet tested. RF-vector focus (BLE / sub-GHz / RFID).

---

*Severity and category are reported here so the scope and significance of the work are visible during the disclosure window. Full detail will be released per device as each vendor window closes.*
