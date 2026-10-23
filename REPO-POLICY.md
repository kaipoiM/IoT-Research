# Repository Policy — Public vs. Private

Two repositories, one rule: **embargoed detail never enters the public repo's history.**

## The two repos

| | Private working repo | Public portfolio repo |
|--|----------------------|------------------------|
| **Visibility** | Private (you + collaborators only) | Public |
| **Contents** | Everything — evidence, raw captures, full reports, disclosure drafts, credentials-free configs | Methodology, tooling, standards, findings *summaries*, disclosure *status* |
| **Purpose** | Complete research record | Grad-school portfolio + eventual public release |
| **Git history** | May contain anything | Must be clean from commit #1 — never contained an embargoed file |

Keeping them as **separate repos** (not one repo flipped between states) is deliberate: it means the public repo's history is clean by construction, so there is never a scrub-the-history problem and never a leak from an old commit.

## What goes where

**Public-safe (belongs in the public repo):**
- `README.md`, methodology, scoring rubric, standards summary
- `docs/legal-ethics.md`, `docs/irb-determination.md`
- `docs/findings-summary.md` — severity + category, no reproduction detail
- `docs/disclosure-status.md` — process + per-vendor stage, no draft contents
- `scripts/` — device-agnostic tooling (no hardcoded targets, creds, or real addresses)
- `tools/configs/` — equipment references with secrets removed
- `experiments/*/README.md` — test *plans*, not results with evidence

**Hold-private until the relevant disclosure window closes:**
- `experiments/*/logs/` — all finding JSONs, pcaps, nmap/traffic output, evidence frames
- Full device reports (`state*-report.md`)
- Firmware images, extracted filesystems, RF captures
- `docs/disclosure/` drafts and vendor correspondence
- Anything containing a real credential, key, cert, MAC, or IP

## Release workflow (per device, as each window closes)

1. Confirm the vendor window has closed or a fix has shipped.
2. Sanitize the evidence for that device (strip real IPs, MACs, credentials, filesystem paths, signed URLs).
3. Move the sanitized finding detail from the private repo into the public repo as a new commit.
4. Update `docs/findings-summary.md` to replace "Embargoed" with the released detail or a link to it.
5. Update `docs/disclosure-status.md`.

## Before the public repo's first push — checklist

- [ ] Repo created fresh (not a clone/fork of the private one — avoids inherited history)
- [ ] `.gitignore` committed **first**, before any content
- [ ] `git status` shows no `logs/`, `*.pcap`, `*-report.md`, keys, or configs with secrets
- [ ] `git log --stat` reviewed — confirm no evidence file appears in any commit
- [ ] Findings summary and disclosure status reviewed for accidental reproduction detail
- [ ] Author identity fields filled in (`README.md`, `disclosure-status.md`)

## Sanitization standard (when evidence is eventually released)

Replace: real device IPs → `192.0.2.x` (RFC 5737 TEST-NET); real MACs → `00:00:5E:00:53:xx` (RFC 7042 doc range); credentials → `[REDACTED]`; local filesystem paths → `/path/`; any signed cloud URL → `[REDACTED-SIGNED-URL]`. Verify binary captures (pcap) separately — a text scrub does not clean a `.pcap`; re-capture sanitized or omit.
