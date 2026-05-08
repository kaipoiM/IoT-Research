# Vulnerability Disclosure Report

> **Use this template for previously undisclosed vulnerabilities only.**
> Vulnerabilities already documented in CVE/NVD or academic literature may be referenced directly.
> Follow CERT/CC coordinated disclosure guidelines.

---

## Vulnerability Summary

| Field | Value |
|-------|-------|
| **Title** | |
| **Affected Vendor** | |
| **Affected Product(s)** | |
| **Affected Firmware Version(s)** | |
| **Vulnerability Type** | (e.g., Improper Certificate Validation, Hardcoded Credentials) |
| **OWASP IoT Category** | (e.g., I1, I7) |
| **CVSS Score** | TBD |
| **CVSS Vector** | TBD |
| **Discovery Date** | |
| **Disclosure Date** | |
| **Researcher** | |

---

## Description

Provide a clear, concise description of the vulnerability: what it is, where it exists in the device/firmware, and why it is a security issue.

---

## Technical Details

### Root Cause

Describe the underlying cause (e.g., missing certificate validation in TLS handshake, hardcoded credential in `/etc/passwd`).

### Attack Scenario

Step-by-step description of how an attacker with network access (or physical access) would exploit this:

1. Attacker positions themselves on the same network segment.
2. ...
3. Result: [describe impact — unauthorized access, data interception, etc.]

### Affected Components

- Firmware version(s):
- Specific binaries / services affected:
- Protocols involved:

---

## Proof of Concept

> Include sanitized PoC — no working exploit code that could be weaponized.
> Reference packet captures in `datasets/pcaps/` or RF captures in `datasets/rf-captures/`.

```
[Sanitized PoC — describe steps, not full exploit code]
```

Evidence files (sanitized, PII removed):
- `datasets/pcaps/[sanitized_filename].pcap`

---

## Impact

- **Confidentiality:** [High / Medium / Low / None]
- **Integrity:** [High / Medium / Low / None]
- **Availability:** [High / Medium / Low / None]

Describe real-world impact: what an attacker gains, what data is exposed, physical consequences (e.g., smart lock bypass).

---

## CVSS 3.1 Score

```
CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N
```

| Metric | Value | Justification |
|--------|-------|--------------|
| Attack Vector | Network / Adjacent / Local / Physical | |
| Attack Complexity | Low / High | |
| Privileges Required | None / Low / High | |
| User Interaction | None / Required | |
| Scope | Unchanged / Changed | |
| Confidentiality Impact | None / Low / High | |
| Integrity Impact | None / Low / High | |
| Availability Impact | None / Low / High | |

**Base Score:** X.X ([Critical / High / Medium / Low])

---

## Standards Violations

| Standard | Provision | Requirement |
|----------|-----------|------------|
| ETSI EN 303 645 | 5.5 | Best-practice cryptography for communication |
| NIST SP 800-213 | §3.2 | Secure authentication for device access |
| OWASP IoT Top 10 | I7 | Insecure data transfer and storage |
| California SB-327 | §1798.91.04 | Reasonable security features |

---

## Recommended Remediation

For the **vendor**:
1. [Specific code fix / configuration change]
2. Distribute firmware update via OTA with signature verification
3. Add remediation to coordinated vulnerability disclosure tracker

For **consumers** (interim mitigation until patch):
1. [E.g., Enable network segmentation, block cloud egress]
2. [E.g., Disable RTSP if not needed]

---

## Disclosure Timeline

| Date | Event |
|------|-------|
| YYYY-MM-DD | Vulnerability discovered during research |
| YYYY-MM-DD | Vendor notified via security contact |
| YYYY-MM-DD | Vendor acknowledgment received |
| YYYY-MM-DD | Patch released (target: 90 days from notification) |
| YYYY-MM-DD | Public disclosure |

**Disclosure policy:** 90-day coordinated disclosure consistent with CERT/CC guidance.
If no vendor response within 30 days, escalate. Public disclosure at 90 days regardless.

---

## References

- CVE: [pending / CVE-XXXX-XXXXX]
- NVD: https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX
- Vendor advisory: [URL]
- CERT/CC: https://www.kb.cert.org/vuls/
