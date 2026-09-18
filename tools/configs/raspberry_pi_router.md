# Raspberry Pi 4B — IoTSecTest Router Configuration

## Device Info

| Field | Value |
|-------|-------|
| **Model** | Raspberry Pi 4B (2GB RAM) |
| **OS** | Raspberry Pi OS Lite 64-bit (Bookworm / Debian 13) |
| **Kernel** | 6.18.34+rpt-rpi-v8 |
| **Onboard WiFi** | BCM4345/6 (brcmfmac driver) — 2.4GHz + 5GHz |
| **Onboard Ethernet** | Gigabit (eth0) |
| **USB WiFi Adapter** | 650Mbps USB adapter, Realtek RTL8821CU (rtw88_8821cu driver) — wlan1, available for monitor mode |
| **AP interface** | wlan0 (onboard) — 5GHz, channel 149 |
| **SD Card** | SanDisk Ultra 64GB microSD |

**Note on previous hardware:** A Raspberry Pi 3B+ was attempted first but found to have corrosion damage. The 3B+ also has a known SD card compatibility issue with Samsung EVO/EVO+ cards (single-blink boot failure). The Pi 4B with SanDisk Ultra resolved both issues.

---

## Network Architecture

```
[IoT Devices / Test Laptops]
        |
    wlan0 (IoTSecTest AP — 192.168.100.1/24)
        |
  Raspberry Pi 4B
        |
    eth0 — SSH admin access only (house network)
           NOT bridged or routed to wlan0
```

The Pi's eth0 connects to the house network (Archer AX4400) for SSH administration only. No routing or bridging exists between eth0 and wlan0 — test devices on wlan0 have no path to the internet or household LAN. Confirmed via mandatory ping test before every session.

---

## Software Stack

| Component | Version | Role |
|-----------|---------|------|
| hostapd | 2:2.10-24 | WiFi AP |
| dnsmasq | 2.91-1+deb13u1 | DHCP + DNS |
| iotsectest.service | custom | Boot-time rfkill unblock + static IP |

---

## Key Bookworm-Specific Notes

Raspberry Pi OS Bookworm differs significantly from older Pi OS versions — these issues will recur if the Pi is rebuilt from scratch:

1. **dhcpcd is not present** — static IP must be assigned via `ip addr` in a custom systemd service, not `/etc/dhcpcd.conf`
2. **wpa_supplicant runs by default and holds WiFi interfaces** — disable it: `sudo systemctl stop wpa_supplicant && sudo systemctl disable wpa_supplicant`
3. **NetworkManager marks WiFi as unmanaged by default** — fix via `managed=true` in `/etc/NetworkManager/NetworkManager.conf` and an unmanaged.conf excluding wlan0
4. **rfkill soft-blocks WiFi on every boot** — must be unblocked via custom systemd service before hostapd starts; manual `rfkill unblock wifi` does not persist across reboots
5. **hostapd is masked by default on Debian** — unmask before enabling: `sudo systemctl unmask hostapd`

---

## Configuration Files

### /etc/NetworkManager/NetworkManager.conf
```
[main]
plugins=ifupdown,keyfile

[ifupdown]
managed=true
```

### /etc/NetworkManager/conf.d/unmanaged.conf
```
[keyfile]
unmanaged-devices=interface-name:wlan0
```

### /etc/hostapd/hostapd.conf
```
interface=wlan0
driver=nl80211
ssid=IoTSecTest
hw_mode=a
channel=149
wmm_enabled=1
ieee80211n=1
ieee80211ac=1
ieee80211d=1
ieee80211h=1
macaddr_acl=1
accept_mac_file=/etc/hostapd/allowed_macs
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=<PASSPHRASE — do not commit to repo>
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
country_code=US
```

### /etc/default/hostapd
```
DAEMON_CONF="/etc/hostapd/hostapd.conf"
```

### /etc/dnsmasq.conf
```
interface=wlan0
dhcp-range=192.168.100.50,192.168.100.150,255.255.255.0,24h
domain=iotsectest.local
address=/#/192.168.100.1
bind-interfaces
```

Note: `address=/#/192.168.100.1` resolves all DNS queries back to the Pi — test devices cannot reach external DNS regardless, but this also lets you see every DNS query a device attempts in dnsmasq logs, which is useful for Phase 1 privacy baseline work.

### /etc/systemd/system/iotsectest.service
```ini
[Unit]
Description=IoTSecTest AP Setup
After=network.target
Before=hostapd.service dnsmasq.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'rfkill unblock wifi; rfkill unblock all; ip addr add 192.168.100.1/24 dev wlan0 2>/dev/null || true'

[Install]
WantedBy=multi-user.target
```

### /etc/systemd/system/hostapd.service.d/override.conf
```ini
[Unit]
After=iotsectest.service
Requires=iotsectest.service
```

### /etc/hostapd/allowed_macs
One MAC per line. Add each device before it attempts to connect — the allowlist is enforced at association, so an unlisted device will associate briefly then immediately disassociate (visible in hostapd logs as associated/disassociated pairs with no DHCP exchange following).

---

## MAC Allowlist

| Device | MAC Address | Date Added |
|--------|-------------|------------|
| Parrot OS laptop (wlp3s0, Intel 8265) | 18:1d:ea:ab:e1:d6 | 2026-09-16 |
| Pixel 8 (monitoring/verification) | 5c:33:7b:e7:c2:e8 | 2026-09-03 |
| Aqara 2K Camera | _fill in during Phase 1_ | |
| LG 43UK6550PUB TV | _fill in during Phase 1_ | |
| KUCACCI Smart Lock (if WiFi gateway equipped) | _fill in during Phase 1_ | |

---

## Services Enabled on Boot

```bash
sudo systemctl enable iotsectest.service
sudo systemctl enable hostapd
sudo systemctl enable dnsmasq
```

Startup order enforced by systemd: `iotsectest.service` (rfkill unblock + static IP) → `hostapd` (AP) → `dnsmasq` (DHCP)

---

## Mandatory Verification (run before every test session)

SSH into the Pi and confirm services are running:
```bash
sudo systemctl status hostapd dnsmasq iotsectest
```

From any device connected to IoTSecTest:
```bash
ping -c 4 8.8.8.8
# Expected: 100% packet loss
```

If the ping succeeds, stop testing immediately — routing has changed. Do not proceed until isolation is re-confirmed.

---

## USB WiFi Adapter (wlan1 — RTL8821CU)

Available as a secondary radio for monitor mode or packet injection. Not used for the AP role. Plug in when needed, leave unplugged otherwise.

To put wlan1 in monitor mode:
```bash
sudo ip link set wlan1 down
sudo iw dev wlan1 set type monitor
sudo ip link set wlan1 up
```

---

## Known Issues / Troubleshooting Log

| Date | Issue | Resolution |
|------|-------|------------|
| 2026-09-03 | Samsung EVO microSD — single blink boot failure on Pi 3B+ | Known compatibility issue with Pi 3B+ SD controller; replaced with SanDisk Ultra on Pi 4B |
| 2026-09-03 | Pi 3B+ board had corrosion damage | Replaced with Pi 4B |
| 2026-09-03 | wpa_supplicant holding wlan0/wlan1, NM showing both as "unavailable" | Disabled wpa_supplicant; set NM managed=true; added unmanaged.conf |
| 2026-09-03 | rfkill soft-blocking WiFi on boot | Created iotsectest.service to unblock before hostapd starts |
| 2026-09-03 | dnsmasq dying silently after startup, no DHCP offers issued | dnsmasq started before wlan0 ready; fixed by service ordering |
| 2026-09-16 | Parrot laptop (Intel 8265) associating but dropping after ~45s, no DHCP | Channel/band mismatch; switched to channel 149 with ieee80211n/ac + wmm_enabled=1 |
