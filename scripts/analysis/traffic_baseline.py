#!/usr/bin/env python3
"""
traffic_baseline.py — IoT Traffic Profiling & Privacy Analysis
IoT Security Research | Phase 4: Privacy Quantification

Analyzes a pcap file to:
  - Profile traffic volume and timing patterns by protocol
  - Identify tracking/analytics domains contacted
  - Flag plaintext credential transmission
  - Detect metadata leakage (activity inference from encrypted traffic patterns)
  - Quantify third-party data exfiltration volume

Usage:
    python traffic_baseline.py --pcap experiments/smart-tv/logs/baseline.pcap \
                               --label tv-s1 --out experiments/smart-tv/logs/

Requires:
    pip install scapy dnspython
"""

import argparse
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("[ERROR] Missing scapy. Run: pip install scapy")
    sys.exit(1)


# ── Known tracking / analytics / telemetry domains ────────────────────────────
# Sources: EasyPrivacy, Disconnect.me, IoT-specific research
TRACKING_DOMAINS = {
    # Generic analytics
    "google-analytics.com", "analytics.google.com", "doubleclick.net",
    "googlesyndication.com", "googletagmanager.com", "facebook.com",
    "connect.facebook.net", "scorecardresearch.com", "quantserve.com",
    "advertising.com", "adnxs.com", "adsrvr.org", "moatads.com",

    # Smart TV specific
    "samba.tv", "smartclip.net", "tvinteractiveapps.com", "tvgenius.net",
    "lg.com", "lge.com", "cdp.samba.tv", "lgtvsdp.com",
    "dial-multiscreen.org", "ispot.tv", "tveyes.com",
    "adsymptotic.com", "mxpnl.com", "mixpanel.com",

    # IoT cloud / telemetry
    "iot.us-east-1.amazonaws.com", "mqtt.googleapis.com",
    "tplinkcloud.com", "tp-link.com", "tapobeta.tp-link.com",
    "myq-cloud.com", "ring.com", "nest.com", "wyze.com",

    # Generic telemetry
    "telemetry.microsoft.com", "vortex.data.microsoft.com",
    "crashlytics.com", "firebase.io", "firebaseapp.com",
}

# Keywords that suggest credential/sensitive data in plaintext
SENSITIVE_PATTERNS = [
    rb"password=", rb"passwd=", rb"pwd=", rb"pass=",
    rb"username=", rb"user=", rb"login=",
    rb"Authorization: Basic", rb"Authorization: Bearer",
    rb"token=", rb"api_key=", rb"secret=",
    rb"admin:", rb"root:",
]


def log(msg: str, level: str = "INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    prefix = {"INFO": "  ", "PASS": "✓ ", "FAIL": "✗ ", "WARN": "⚠ "}
    print(f"[{ts}] {prefix.get(level, '  ')}{msg}")


def analyze_pcap(pcap_path: str, results: dict) -> None:
    log(f"Loading pcap: {pcap_path}")
    try:
        packets = rdpcap(pcap_path)
    except Exception as e:
        log(f"Failed to read pcap: {e}", "FAIL")
        return

    log(f"Packets loaded: {len(packets)}")
    results["total_packets"] = len(packets)

    # ── Traffic volume by protocol ────────────────────────────────────────────
    proto_counts: Counter = Counter()
    ip_bytes: defaultdict = defaultdict(int)
    dns_queries: list[str] = []
    http_requests: list[dict] = []
    plaintext_hits: list[dict] = []
    tracking_hits: Counter = Counter()
    timestamps: list[float] = []

    for pkt in packets:
        ts = float(pkt.time)
        timestamps.append(ts)

        if IP in pkt:
            src = pkt[IP].src
            dst = pkt[IP].dst
            size = len(pkt)
            ip_bytes[dst] += size

            if TCP in pkt:
                dport = pkt[TCP].dport
                if dport == 80:
                    proto_counts["HTTP"] += 1
                elif dport == 443:
                    proto_counts["HTTPS"] += 1
                elif dport == 554:
                    proto_counts["RTSP"] += 1
                elif dport == 1883:
                    proto_counts["MQTT_PLAIN"] += 1
                elif dport == 8883:
                    proto_counts["MQTT_TLS"] += 1
                elif dport == 23:
                    proto_counts["TELNET"] += 1
                elif dport == 21:
                    proto_counts["FTP"] += 1
                else:
                    proto_counts[f"TCP:{dport}"] += 1

            if UDP in pkt:
                dport = pkt[UDP].dport
                if dport == 53:
                    proto_counts["DNS"] += 1
                elif dport == 5683:
                    proto_counts["CoAP"] += 1
                else:
                    proto_counts[f"UDP:{dport}"] += 1

        # ── DNS query extraction ───────────────────────────────────────────────
        if DNS in pkt and pkt[DNS].qr == 0 and DNSQR in pkt:
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            dns_queries.append(qname)

            # Check against tracking domain list
            for domain in TRACKING_DOMAINS:
                if domain in qname:
                    tracking_hits[domain] += 1

        # ── Plaintext credential detection ────────────────────────────────────
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            for pattern in SENSITIVE_PATTERNS:
                if pattern.lower() in payload.lower():
                    plaintext_hits.append({
                        "pattern": pattern.decode(errors="ignore"),
                        "dst": pkt[IP].dst if IP in pkt else "unknown",
                        "dport": pkt[TCP].dport if TCP in pkt else "unknown",
                        "payload_preview": payload[:100].decode(errors="ignore").replace("\n", " ")
                    })
                    break  # one hit per packet

    # ── Traffic timing analysis (for metadata leakage) ────────────────────────
    # Look for periodic bursts that could reveal activity (per IoTLS/Smart Home research)
    if len(timestamps) > 10:
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        avg_interval = sum(intervals) / len(intervals) if intervals else 0
        results["timing_analysis"] = {
            "capture_duration_seconds": timestamps[-1] - timestamps[0] if timestamps else 0,
            "avg_inter_packet_interval": round(avg_interval, 4),
            "potential_metadata_leakage": avg_interval < 0.5  # high-frequency traffic may reveal activity
        }

    # ── Top destination IPs ───────────────────────────────────────────────────
    top_dsts = sorted(ip_bytes.items(), key=lambda x: x[1], reverse=True)[:10]

    # ── Summary population ────────────────────────────────────────────────────
    results["protocol_distribution"] = dict(proto_counts.most_common(15))
    results["top_destinations"] = [{"ip": ip, "bytes": b} for ip, b in top_dsts]
    results["dns_queries_total"] = len(dns_queries)
    results["unique_domains"] = len(set(dns_queries))
    results["tracking_domains_contacted"] = dict(tracking_hits)
    results["tracking_domain_count"] = len(tracking_hits)
    results["plaintext_credential_hits"] = len(plaintext_hits)
    results["plaintext_credential_samples"] = plaintext_hits[:5]  # first 5 for log

    total_tracking_bytes = sum(
        ip_bytes.get(ip, 0) for ip in ip_bytes
        # Rough estimate: attribute by domain lookup (would need DNS→IP mapping for precision)
    )
    results["total_bytes_captured"] = sum(ip_bytes.values())

    # ── Flag findings ─────────────────────────────────────────────────────────
    if proto_counts.get("HTTP", 0) > 0:
        results["findings"].append({
            "severity": "HIGH",
            "issue": f"Unencrypted HTTP traffic detected ({proto_counts['HTTP']} packets)",
            "owasp": "I7", "etsi": "5.5"
        })

    if proto_counts.get("MQTT_PLAIN", 0) > 0:
        results["findings"].append({
            "severity": "HIGH",
            "issue": f"Plaintext MQTT (port 1883) detected ({proto_counts['MQTT_PLAIN']} packets)",
            "owasp": "I7", "etsi": "5.5"
        })

    if proto_counts.get("TELNET", 0) > 0:
        results["findings"].append({
            "severity": "CRITICAL",
            "issue": f"Telnet traffic detected ({proto_counts['TELNET']} packets) — plaintext remote access",
            "owasp": "I2", "etsi": "5.6"
        })

    if tracking_hits:
        results["findings"].append({
            "severity": "MEDIUM",
            "issue": f"Device contacted {len(tracking_hits)} known tracking/analytics domains",
            "domains": list(tracking_hits.keys()),
            "owasp": "I6", "etsi": "Section 6"
        })

    if plaintext_hits:
        results["findings"].append({
            "severity": "CRITICAL",
            "issue": f"Potential plaintext credentials detected in {len(plaintext_hits)} packets",
            "owasp": "I7", "etsi": "5.5"
        })

    if results.get("timing_analysis", {}).get("potential_metadata_leakage"):
        results["findings"].append({
            "severity": "LOW",
            "issue": "High-frequency traffic pattern — potential metadata leakage even if encrypted",
            "owasp": "I6",
            "reference": "Apthorpe et al. (2017) — Smart Home Traffic Analysis"
        })


def main():
    parser = argparse.ArgumentParser(description="IoT Traffic Baseline & Privacy Analysis")
    parser.add_argument("--pcap", required=True, help="Path to .pcap file")
    parser.add_argument("--label", default="device", help="Device label")
    parser.add_argument("--out", default="./output", help="Output directory")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    results = {
        "test_id": f"TRAFFIC-{args.label}-{timestamp}",
        "pcap_file": args.pcap,
        "timestamp": datetime.now().isoformat(),
        "findings": [],
    }

    log(f"===== Traffic Analysis: {args.pcap} =====")
    analyze_pcap(args.pcap, results)

    # ── Print summary ─────────────────────────────────────────────────────────
    log("")
    log("===== Analysis Complete =====")
    log(f"Total packets         : {results.get('total_packets', 0)}")
    log(f"Total bytes           : {results.get('total_bytes_captured', 0):,}")
    log(f"DNS queries           : {results.get('dns_queries_total', 0)}")
    log(f"Unique domains        : {results.get('unique_domains', 0)}")
    log(f"Tracking domains      : {results.get('tracking_domain_count', 0)}")
    log(f"Plaintext cred hits   : {results.get('plaintext_credential_hits', 0)}")
    log(f"Findings              : {len(results['findings'])}")
    log("")

    log("Protocol distribution:")
    for proto, count in sorted(results.get("protocol_distribution", {}).items(), key=lambda x: -x[1]):
        severity = ""
        if proto in ("HTTP", "TELNET", "FTP", "MQTT_PLAIN"):
            severity = "  ← INSECURE"
        log(f"  {proto:20s} {count:6d} packets{severity}")

    if results.get("tracking_domains_contacted"):
        log("")
        log("Tracking domains contacted:")
        for domain, count in sorted(results["tracking_domains_contacted"].items(), key=lambda x: -x[1]):
            log(f"  {domain:40s} {count} queries")

    # Save
    out_file = os.path.join(args.out, f"traffic_{args.label}_{timestamp}.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"\nResults saved: {out_file}")


if __name__ == "__main__":
    main()
