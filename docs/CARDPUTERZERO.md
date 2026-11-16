# CardputerZero operation guide

GainSec GITM `0.1.0` provides an authorized WPA2 AP with DHCP, DNS forwarding, and NAT over a physical wired-Ethernet WAN. TLS interception and packet capture are not included.

## Install and authorize

Build `dist/gainsec-gitm_0.1.0-1_arm64.deb` from the public checkout, copy it to the device, and run:

```sh
sudo apt install ./gainsec-gitm_0.1.0-1_arm64.deb
sudo usermod -aG gainsec-gitm "$USER"
sudo systemctl enable --now gainsec-gitm-helper.socket
```

Log out and back in after changing group membership. The `gainsec-gitm` Unix group is the authorization boundary for the group-restricted helper socket. The GUI acknowledgment is only an operator reminder and grants no privilege.

The package requires NetworkManager and `nmcli`. It also requires an AP-capable Wi-Fi interface and a linked physical wired-Ethernet WAN. Preflight fails closed when any prerequisite is unavailable.

## Operate through APPLaunch

1. Connect the wired-Ethernet WAN.
2. Open **GainSec GITM**.
3. Press `C`, Space, or Enter to run preflight.
4. Review the detected interfaces, network defaults, generated session credentials, and disabled features.
5. Press `C` to acknowledge authorization, then press `C` again to start.
6. Connect only authorized clients using the credentials displayed on the device.
7. Press `C` from **ACTIVE** to stop and restore owned state.

Use short `Z` or Escape presses to go back. APPLaunch owns the long Escape hold and may terminate the application process group.

The general CLI supports read-only checks:

```sh
gitm status --backend system
gitm preflight --backend system
gitm render-plan --backend system
```

## Owned state and rollback

The helper owns only its directly parented hostapd/dnsmasq processes, `/run/gainsec-gitm/private`, its bounded event log, the `gitm-ap` interface, and `table inet gainsec_gitm`. It records the previous IPv4-forwarding value and restores it during stop or rollback. It does not flush global firewall state.

Immediately after creating `gitm-ap`, the helper marks it unmanaged before assigning an address or bringing it up. Cleanup removes the wireless VIF with `iw dev gitm-ap del`.

Corrupt, unreadable, or foreign ownership state blocks start, stop, and package removal rather than being overwritten. If cleanup fails, retain the state files and inspect:

```sh
systemctl status gainsec-gitm-helper.socket gainsec-gitm-helper.service
journalctl -u gainsec-gitm-helper.service
```

## Uninstall

Stop an active session first, verify status, and remove the package:

```sh
gitm status --backend system
sudo apt remove gainsec-gitm
```

Removal deliberately fails if the helper cannot prove that owned network state was cleaned. Do not force-delete recovery state.

## Physical acceptance status

The packaged dataplane has been exercised on a Debian 13 ARM64 CardputerZero using the onboard Wi-Fi radio and a linked physical USB-Ethernet WAN. A real client received a `192.168.77.0/24` DHCP lease with the package gateway and DNS server, resolved public DNS through dnsmasq, reached HTTPS through Ethernet NAT, and could not open device SSH from the AP. The helper remained active beyond stabilization. Stop then proved hostapd and dnsmasq absent, `gitm-ap` absent, `table inet gainsec_gitm` absent, private ownership state removed, and the prior IPv4-forwarding value restored.

The installed icon and 320×170 framebuffer route were verified. Physical keyboard navigation and launch selection through the APPLaunch menu remain the final UI acceptance gates before describing the complete release as device-verified.
