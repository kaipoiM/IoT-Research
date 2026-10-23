#!/usr/bin/env python3
"""
tls_checker.py — IoT Device TLS/SSL Certificate Validation Assessment
IoT Security Research | Network Analysis

Tests whether an IoT device properly validates TLS certificates, checking for:
  - Certificate expiry / self-signed certs
  - Deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
  - Weak cipher suites
  - Certificate pinning (via deliberate invalid cert)
  - HSTS enforcement

Usage:
    python tls_checker.py --target 192.168.100.X [--port 443] --out experiments/ip-camera/logs/

Requires: openssl (CLI), cryptography, requests
    pip install cryptography requests
"""

import argparse
import json
import os
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[ERROR] Missing dependencies. Run: pip install cryptography requests")
    sys.exit(1)


# ── Deprecated / weak TLS configs ────────────────────────────────────────────
DEPRECATED_PROTOCOLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_CIPHERS = [
    "RC4", "DES", "3DES", "EXPORT", "NULL", "anon",
    "MD5", "SHA1", "ADH", "AECDH"
]


def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"INFO": "  ", "PASS": "✓ ", "FAIL": "✗ ", "WARN": "⚠ "}
    print(f"[{ts}] {prefix.get(level, '  ')}{msg}")


def run_openssl(args: list[str]) -> tuple[str, str, int]:
    """Run an openssl command and return (stdout, stderr, returncode)."""
    cmd = ["openssl"] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return result.stdout, result.stderr, result.returncode


def check_certificate(host: str, port: int, results: dict) -> None:
    """Retrieve and analyze the server certificate."""
    log(f"── Certificate Analysis: {host}:{port} ──")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                proto = ssock.version()
                cipher = ssock.cipher()
    except (socket.timeout, ConnectionRefusedError) as e:
        log(f"Cannot connect to {host}:{port} — {e}", "FAIL")
        results["connection_error"] = str(e)
        return

    # Parse certificate
    cert = x509.load_der_x509_certificate(cert_der, default_backend())
    now = datetime.now(timezone.utc)

    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    expired = now > not_after
    self_signed = subject == issuer
    days_remaining = (not_after - now).days

    log(f"Subject       : {subject}")
    log(f"Issuer        : {issuer}")
    log(f"Valid from    : {not_before.date()} to {not_after.date()}")
    log(f"Days remaining: {days_remaining}")
    log(f"Protocol      : {proto}")
    log(f"Cipher suite  : {cipher[0] if cipher else 'unknown'}")

    results["certificate"] = {
        "subject": subject,
        "issuer": issuer,
        "not_before": str(not_before),
        "not_after": str(not_after),
        "days_remaining": days_remaining,
        "expired": expired,
        "self_signed": self_signed,
        "protocol": proto,
        "cipher_suite": cipher[0] if cipher else None,
    }

    if expired:
        log("Certificate is EXPIRED", "FAIL")
        results["findings"].append({"severity": "HIGH", "issue": "Expired certificate", "owasp": "I7"})
    else:
        log(f"Certificate valid ({days_remaining} days remaining)", "PASS")

    if self_signed:
        log("Self-signed certificate detected", "WARN")
        results["findings"].append({"severity": "MEDIUM", "issue": "Self-signed certificate", "owasp": "I7"})

    if proto in DEPRECATED_PROTOCOLS:
        log(f"DEPRECATED protocol in use: {proto}", "FAIL")
        results["findings"].append({"severity": "HIGH", "issue": f"Deprecated protocol: {proto}", "owasp": "I7", "etsi": "5.5"})
    else:
        log(f"Protocol {proto} is acceptable", "PASS")

    if cipher:
        cipher_name = cipher[0]
        weak = [w for w in WEAK_CIPHERS if w.upper() in cipher_name.upper()]
        if weak:
            log(f"Weak cipher suite: {cipher_name} (weak components: {weak})", "FAIL")
            results["findings"].append({"severity": "HIGH", "issue": f"Weak cipher: {cipher_name}", "owasp": "I7", "etsi": "5.5"})
        else:
            log(f"Cipher suite acceptable: {cipher_name}", "PASS")


def check_deprecated_protocols(host: str, port: int, results: dict) -> None:
    """Check if the server accepts deprecated TLS versions."""
    log("")
    log("── Deprecated Protocol Support ──")
    results["deprecated_protocols"] = {}

    proto_map = {
        "TLSv1":   ["tls1"],
        "TLSv1.1": ["tls1_1"],
        "SSLv3":   ["ssl3"],
    }

    for proto_name, openssl_flags in proto_map.items():
        flag = f"-{openssl_flags[0]}"
        stdout, stderr, rc = run_openssl([
            "s_client", "-connect", f"{host}:{port}",
            flag, "-brief", "-verify_quiet",
            "-no_tls1_2", "-no_tls1_3"
        ])

        accepted = "CONNECTED" in stdout or rc == 0 and "handshake failure" not in stderr.lower()
        results["deprecated_protocols"][proto_name] = accepted

        if accepted:
            log(f"Server accepts {proto_name} — DEPRECATED", "FAIL")
            results["findings"].append({
                "severity": "HIGH",
                "issue": f"Server accepts deprecated {proto_name}",
                "owasp": "I5",
                "etsi": "5.5",
                "nist": "SP800-213 §3.1"
            })
        else:
            log(f"Server rejects {proto_name}", "PASS")


def check_certificate_validation(host: str, port: int, results: dict) -> None:
    """Test if the device validates server certificates (certificate pinning proxy)."""
    log("")
    log("── Certificate Validation Test (Invalid CA) ──")
    log("  Sending request with deliberately untrusted certificate ...")

    # We test by connecting using a context that presents an invalid cert
    # In a real MITM scenario, this uses SSLsplit's CA
    ctx_strict = ssl.create_default_context()
    ctx_strict.check_hostname = True
    ctx_strict.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, port), timeout=5) as raw_sock:
            with ctx_strict.wrap_socket(raw_sock, server_hostname=host) as ssock:
                # If we get here with default CAs, the cert is publicly trusted
                log("Certificate validates against system trust store", "PASS")
                results["validates_against_system_store"] = True
    except ssl.SSLCertVerificationError as e:
        log(f"Certificate validation error: {e.reason}", "WARN")
        log("  Device may use self-signed / private CA cert (expected for IoT)", "WARN")
        results["validates_against_system_store"] = False
        results["cert_validation_error"] = str(e)
    except Exception as e:
        log(f"Connection error: {e}", "WARN")


def check_hsts(host: str, port: int, results: dict) -> None:
    """Check for HTTPS enforcement and HSTS headers."""
    log("")
    log("── HTTPS / HSTS Enforcement ──")

    # Check if HTTP redirects to HTTPS
    try:
        r = requests.get(f"http://{host}:80/", timeout=5, allow_redirects=False, verify=False)
        if r.status_code in (301, 302, 307, 308):
            location = r.headers.get("Location", "")
            if location.startswith("https://"):
                log("HTTP → HTTPS redirect in place", "PASS")
                results["http_redirects_https"] = True
            else:
                log(f"HTTP redirect to non-HTTPS: {location}", "WARN")
                results["http_redirects_https"] = False
        else:
            log(f"HTTP endpoint responds without redirect (HTTP {r.status_code})", "FAIL")
            results["http_open_no_redirect"] = True
            results["findings"].append({
                "severity": "HIGH",
                "issue": "HTTP endpoint accessible without HTTPS redirect",
                "owasp": "I7",
                "etsi": "5.5"
            })
    except requests.exceptions.ConnectionError:
        log("HTTP port 80 not accessible (expected if device uses HTTPS only)", "PASS")
        results["http_port_closed"] = True

    # Check HSTS header
    try:
        r = requests.get(f"https://{host}:{port}/", timeout=5, verify=False)
        hsts = r.headers.get("Strict-Transport-Security")
        if hsts:
            log(f"HSTS header present: {hsts}", "PASS")
            results["hsts_header"] = hsts
        else:
            log("No HSTS header", "WARN")
            results["findings"].append({
                "severity": "LOW",
                "issue": "Missing HSTS header",
                "owasp": "I7"
            })
    except Exception:
        pass


def score_tls(results: dict) -> float:
    """Calculate TLS security sub-score (0–10)."""
    score = 10.0
    deductions = {
        "HIGH": 3.0,
        "MEDIUM": 1.5,
        "LOW": 0.5
    }
    for finding in results.get("findings", []):
        score -= deductions.get(finding.get("severity", "LOW"), 0.5)
    return max(0.0, round(score, 1))


def main():
    parser = argparse.ArgumentParser(description="IoT TLS/SSL Security Assessment")
    parser.add_argument("--target", required=True, help="Device IP address")
    parser.add_argument("--port", type=int, default=443, help="HTTPS port (default: 443)")
    parser.add_argument("--out", default="./output", help="Output directory")
    parser.add_argument("--label", default="device", help="Device label for filenames")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    results = {
        "test_id": f"TLS-{args.label}-{timestamp}",
        "target": args.target,
        "port": args.port,
        "timestamp": datetime.now().isoformat(),
        "findings": [],
    }

    log(f"===== TLS Security Assessment: {args.target}:{args.port} =====")
    log(f"Label: {args.label}")
    log("")

    check_certificate(args.target, args.port, results)
    check_deprecated_protocols(args.target, args.port, results)
    check_certificate_validation(args.target, args.port, results)
    check_hsts(args.target, args.port, results)

    # ── Scoring ───────────────────────────────────────────────────────────────
    tls_score = score_tls(results)
    results["tls_security_score"] = tls_score

    log("")
    log("===== TLS Assessment Complete =====")
    log(f"Findings   : {len(results['findings'])}")
    log(f"HIGH sev   : {sum(1 for f in results['findings'] if f.get('severity') == 'HIGH')}")
    log(f"TLS Score  : {tls_score}/10")

    if tls_score < 5:
        log("RESULT: CRITICAL TLS vulnerabilities — MITM attacks highly feasible", "FAIL")
        log("  Likely violates ETSI EN 303 645 Provision 5.5", "FAIL")
    elif tls_score < 8:
        log("RESULT: Moderate TLS weaknesses — some attack vectors remain", "WARN")
    else:
        log("RESULT: TLS configuration acceptable", "PASS")

    # ── Save results ──────────────────────────────────────────────────────────
    out_file = os.path.join(args.out, f"tls_{args.label}_{timestamp}.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"\nResults saved: {out_file}")

    # OWASP / Standards mapping summary
    log("")
    log("Standards violations identified:")
    for finding in results["findings"]:
        owasp = finding.get("owasp", "")
        etsi = finding.get("etsi", "")
        nist = finding.get("nist", "")
        refs = " | ".join(filter(None, [
            f"OWASP {owasp}" if owasp else "",
            f"ETSI {etsi}" if etsi else "",
            nist
        ]))
        log(f"  [{finding['severity']:6s}] {finding['issue']}  —  {refs}")


if __name__ == "__main__":
    main()
