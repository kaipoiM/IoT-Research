# Interim Test Network — Archer AX4400 Guest Network

## Status

**This is a temporary stopgap**, in use because the planned Raspberry Pi 3B+ dedicated router (see `tools/configs/raspberry_pi_router.md`) is currently blocked by an SD card compatibility issue — Samsung EVO/EVO+ microSD cards have a documented boot failure on the Pi 3B/3B+ (boot ROM single-flash LED error, card cannot be read), independent of formatting/partitioning. A replacement card has been ordered.

**Switch back to the Pi-based setup once the new card confirms the Pi boots successfully.** The Pi remains the preferred long-term setup — see `tools/configs/raspberry_pi_router.md` for why it provides a stronger isolation guarantee (physically separate hardware with no WAN interface at all, vs. a software toggle on shared hardware).

---

## Why This Is a Weaker Isolation Guarantee (Read Before Using)

Unlike the Pi setup, this interim network:
- Runs on the **same physical router and firmware** as your household network (TP-Link Archer AX4400), not separate hardware
- Relies on a **software toggle** ("Internet Access: OFF") to prevent WAN access, rather than the router having no uplink to bridge at all
- Could silently lose isolation if a firmware bug, accidental setting change, or router reboot reverts the toggle, with no obvious external sign

**This is a real, disclosed limitation — document it explicitly in your final report's methodology/limitations section.** A reviewer will respect an honestly-documented equipment constraint far more than an unstated gap. Something like: *"Due to an SD card compatibility issue delaying the dedicated isolated router build, initial testing (Weeks X–Y) used the household router's guest network feature with internet access disabled as an interim isolation measure, verified via connectivity testing before each session, before transitioning to a physically separate Raspberry Pi-based router for the remainder of testing."*

**Because of this weaker guarantee, the verification test below is mandatory before every single test session, no exceptions.**

---

## Configuration Steps

Access the Archer AX4400 admin panel — typically `http://192.168.0.1` or `http://tplinkwifi.net` — then:

1. Navigate to **Wireless > Guest Network**
2. Enable the **2.4GHz** Guest Network (2.4GHz matches typical IoT device defaults and keeps band consistent with what you'd be using on the Pi later)
3. Set SSID: `IoTSecTest`
4. Set a WPA2 passphrase — **do not reuse your main household network's passphrase**
5. **Set both of these — this is the core isolation control:**
   - **Allow guest to access my local network:** OFF
   - **Internet Access:** OFF
6. Save, and reboot the guest radio if the router prompts for it

### Access Control

| Setting | Value |
|---------|-------|
| Test SSID | `IoTSecTest` |
| Guest → local network access | OFF |
| Guest → internet access | OFF (**re-verify every session**) |
| MAC filtering | Check **Advanced > Security > Access Control** on the AX4400 — if it applies to the guest network specifically, enable allowlist mode. If the firmware only supports Access Control on the main network, note this as a further limitation and rely on WPA2 passphrase + short, supervised test windows as compensating controls. |
| Allowlisted MAC(s) | _fill in as each device is added_ |

| Device | MAC Address | Date Added |
|--------|-------------|------------|
| Aqara 2K Camera | | |
| LG 43UK6550PUB TV | | |
| KUCACCI Smart Lock (if WiFi-gateway equipped) | | |
| Kali Linux laptop | | |

---

## Verification Test — Run Before Every Session, No Exceptions

```bash
# From a device connected to IoTSecTest guest network:
ping -c 4 8.8.8.8
```

**Expected result: 100% packet loss / no route to host.**

If this ping succeeds, **stop testing immediately.** The Internet Access toggle has reverted, or another isolation failure has occurred. Re-check guest network settings in the AX4400 admin panel before doing anything else.

---

## Transition Plan Back to Pi-Based Router

1. New SD card arrives → flash Raspberry Pi OS Lite fresh, following `tools/configs/raspberry_pi_router.md`
2. Boot Pi, confirm LED behavior indicates successful boot (not the single-repeating-flash card-read error seen previously)
3. If boot succeeds, complete the hostapd/dnsmasq setup in that document
4. Run the Pi-based verification test
5. Once confirmed working, disable the Archer AX4400 guest network entirely (don't leave two "isolated" networks active simultaneously — pick one, and make sure devices/logs clearly indicate which network each test session used)
6. Update `docs/test-network-setup-checklist.md` and any test logs already generated to note which sessions ran on which interim/final network, for methodology transparency
