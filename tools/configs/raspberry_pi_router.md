# Raspberry Pi 3B+ — IoTSecTest Router Configuration

## Device Info

| Field | Value |
|-------|-------|
| **Model** | Raspberry Pi 3B+ (1GB RAM) |
| **Onboard WiFi** | BCM43438 — 2.4GHz only (no 5GHz support) |
| **Onboard Ethernet** | 10/100 (sufficient for this role — not internet-facing) |
| **OS** | Raspberry Pi OS Lite (recommended — headless, no desktop overhead needed) |
| **Role** | Dedicated, isolated AP for `IoTSecTest` — no WAN uplink, no bridge to house network |

**2.4GHz-only note:** confirm each device under test can associate on 2.4GHz. Most consumer IoT devices (cameras, locks, sensors) default to 2.4GHz specifically because it's the common denominator, so this is unlikely to be a blocker, but verify during Phase 1 recon rather than assuming.

---

## Why This Setup Satisfies Isolation Requirements

Per `docs/legal-ethics.md`, the test network must have "no connection to production networks, Internet services, or third-party systems." This Pi build satisfies that architecturally, not just by configuration toggle:

- The Pi's Ethernet port is **not connected to the house network or the Archer AX4400** at all — leave it unplugged, or plug it into an isolated switch with no other uplink.
- No WAN interface is configured in software. There is no "internet access" setting to accidentally leave on, unlike a consumer router's guest network — the Pi simply has no path out.
- This is a stronger isolation guarantee than the Archer AX4400 guest-network approach, since it doesn't rely on a single toggle in vendor firmware you don't control.

---

## Software Stack

| Component | Purpose |
|-----------|---------|
| `hostapd` | Runs the WiFi access point (SSID `IoTSecTest`) |
| `dnsmasq` | DHCP + DNS for the isolated test subnet |
| `iptables` (optional) | Only needed if you want the Pi to also NAT/log traffic between subnet devices; not needed for a fully offline test segment |

Install:
```bash
sudo apt update
sudo apt install hostapd dnsmasq
sudo systemctl unmask hostapd
```

---

## Network Configuration

### Static IP for the Pi's WiFi interface (wlan0)

Edit `/etc/dhcpcd.conf`, add:
```
interface wlan0
    static ip_address=192.168.100.1/24
    nohook wpa_supplicant
```

### dnsmasq — DHCP scope for test devices

Edit `/etc/dnsmasq.conf`:
```
interface=wlan0
dhcp-range=192.168.100.50,192.168.100.150,255.255.255.0,24h
domain=iotsectest.local
address=/#/192.168.100.1
```

Note: `address=/#/192.168.100.1` resolves ALL DNS queries to the Pi itself, which is a deliberate choice — since there is no WAN uplink, devices under test cannot reach real DNS servers or the internet regardless, but this makes that explicit and gives you a place to observe/log every DNS query a device attempts to make (useful for Phase 4 privacy analysis groundwork, even though real traffic-baseline analysis happens via `scripts/analysis/traffic_baseline.py` on captured pcaps).

### hostapd — AP configuration

Edit `/etc/hostapd/hostapd.conf`:
```
interface=wlan0
driver=nl80211
ssid=IoTSecTest
hw_mode=g
channel=6
wmm_enabled=0
macaddr_acl=1
accept_mac_file=/etc/hostapd/allowed_macs
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=<CHOOSE A STRONG PASSPHRASE — do not commit to repo>
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
```

Point hostapd to this config in `/etc/default/hostapd`:
```
DAEMON_CONF="/etc/hostapd/hostapd.conf"
```

### MAC allowlist (`macaddr_acl=1` above enforces this)

Create `/etc/hostapd/allowed_macs`:
```
# One MAC per line — add each device as it's brought into testing
# Aqara 2K Camera:
# LG 43UK6550PUB TV:
# KUCACCI Lock (if WiFi-gateway equipped):
# Kali Linux laptop:
```
Populate from the table in `docs/test-network-setup-checklist.md` Section 2.

### Enable services
```bash
sudo systemctl enable hostapd
sudo systemctl enable dnsmasq
sudo systemctl start hostapd
sudo systemctl start dnsmasq
```

---

## Verification (run every session, not just once)

```bash
# From a device connected to IoTSecTest:
ping -c 4 8.8.8.8
# Expected: 100% packet loss — confirms no path to internet exists
```

If this ever succeeds, something has bridged the test network to a live uplink — stop testing immediately and investigate before proceeding. This is the same check specified in `docs/test-network-setup-checklist.md` Section 1; the Pi setup doesn't change that requirement, it just changes how confident you can be that the check will keep passing.

---

## Packet Capture on the Pi Itself (optional, supplements Kali laptop capture)

Since the Pi sees all traffic as the AP, it can also run a baseline tcpdump if useful for redundancy:
```bash
sudo tcpdump -i wlan0 -w /home/pi/captures/baseline_$(date +%Y%m%d_%H%M%S).pcap
```
Transfer captures off the Pi regularly (SCP or SD card removal) — 1GB RAM and typical SD card storage will fill up faster than the Kali laptop's dedicated capture storage.

---

## Known Limitations of This Setup

- **2.4GHz only** — if any device under test requires 5GHz to expose its full feature set (unlikely for this device set, but worth confirming), this Pi can't host that band. A USB WiFi adapter with 5GHz + AP mode support would be needed as a workaround.
- **Single Ethernet port** — if you want the Pi to also route to a second isolated segment (e.g., separating RF-only devices from WiFi devices), you'd need a USB Ethernet adapter or manage it entirely over WiFi.
- **1GB RAM** — fine for hostapd/dnsmasq/tcpdump simultaneously, but avoid also running heavy analysis scripts on the Pi itself; keep `pcap_parser.py`, `tls_checker.py`, etc. on the Kali laptop as originally planned.

---

## Known Issues / Troubleshooting Log

_Add entries as you encounter and resolve issues during setup._

| Date | Issue | Resolution |
|------|-------|------------|
| | | |
