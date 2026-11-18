# CardputerZero operations — GITM 0.2.1

The native app operates a physical AP-capable wireless interface and a separate linked physical Ethernet WAN. It configures only `gitm-ap` and the `inet gainsec_gitm` nftables table. It preserves the pre-existing IPv4 forwarding value and refuses occupied, corrupt or foreign state.

## Device installation

```sh
sudo apt install ./gainsec-gitm_0.2.1-1_arm64.deb
sudo adduser "$USER" gainsec-gitm
# Log out/in before the following commands.
systemctl status gainsec-gitm-helper.socket
gitm preflight --backend system
gitm gui --backend system
```

APPLaunch entry: `/usr/share/APPLaunch/applications/gitm.desktop`; launcher executable: `/usr/share/GITM/bin/gitm`. The helper socket is `/run/gainsec-gitm/helper.sock`, mode 0660, group `gainsec-gitm`. No broad privilege grant is installed. Root code imports only package-owned code, validates a canonical plan, and binds evidence ownership to the Unix peer UID. Custom CA files are read without privilege in the frontend; validated PEM data travels in memory over the socket.

On the C0, the GUI renders RGB565 directly to `/dev/fb_lcd` using SDL's dummy display driver and reads `/dev/input/cardputer-zero-internal` without grabbing the keyboard. This supports the internal keyboard's separate input seat; APPLaunch still owns held Escape. Existing `video` and `input` group membership is required. A desktop without the C0 framebuffer uses normal SDL input/display. An explicitly set `SDL_VIDEODRIVER` is respected.

The GUI is 320×170 and mirrors RGB565 to `/dev/fb_lcd` when available. C/Enter selects; F/X or left/right/Tab switches pages; W/S or up/down scrolls. On SETTINGS, Enter toggles a boolean or opens text entry. Enter saves; Escape cancels. On TRAFFIC, C cycles live, lease, and TLS connection metadata. On PROFILES, C verifies/selects a recovered profile; the final row restores local/custom CA mode. EXPORTS prepares Android, Burp, or both at the directory set in SETTINGS. EVIDENCE shows paths, including wrapped export paths. SETTINGS remains locked during an active session.

The simulator never claims hardware success: status includes `simulated: true`, and no AP/daemon/capture is created. Certificate preparation in simulation creates disposable lab credentials only when explicitly requested.

## Configure and operate

```sh
gitm configure --backend system --config "$HOME/gitm-lab.json" \
  --ap-interface wlan0 --wan-interface eth0 --country US \
  --dump --capture-mb 8 --live --strip --lease-events
gitm render-plan --backend system --config "$HOME/gitm-lab.json"
gitm start --backend system --config "$HOME/gitm-lab.json" --dry-run
gitm gui --backend system --config "$HOME/gitm-lab.json"
# Alternatively:
gitm start --backend system --config "$HOME/gitm-lab.json" --authorized
gitm status --backend system
gitm inspect --backend system --kind leases --limit 10
gitm inspect --backend system --kind live --limit 10
gitm inspect --backend system --kind tls --limit 10
gitm export --backend system --android --burp --output-dir "$HOME/gitm-exports"
gitm stop --backend system
```

Use a complete verifiable parent chain for custom subordinate CAs. Validation checks strict PEM structure, matching public key, CA:TRUE, keyCertSign, validity, issuer/signature links, path lengths and the self-signed trust anchor. Custom material and a bundled profile are mutually exclusive. For profile exports, choose the same `--emudhra NAME` as the session. Otherwise export prepares/reuses the per-user local CA. All twelve original recovered profiles are included, pinned and verified; modern clients should reject these revoked CAs.

Evidence is finite and private. Status returns exact paths under `/var/lib/gainsec-gitm/users/<uid>/`. A new session truncates its selected evidence files; copy them first. Capture is one full-packet rotating PCAP, 1–64 MB plus one packet overhead. Live/lease JSONL is bounded to 256 KiB each; SSLsplit connection logging is bounded to 512 KiB by the kernel. The helper checks liveness and disk reserve every 250 ms while idle and after serving requests. If a worker dies or storage reserve is exhausted it tears down networking. Explicit `gitm stop` clears a watchdog failure after successful cleanup. A long-running connection can make inspection metadata arrive later; no decrypted packet payload is rendered.

The systemd service needs network capabilities plus CAP_KILL for dnsmasq after privilege drop, CAP_SETUID/CAP_SETGID for daemon transitions, and CAP_CHOWN/CAP_DAC_OVERRIDE/CAP_FOWNER to create and maintain requester-owned 0600 evidence inside fixed helper-owned directories. Its writable paths are restricted to its runtime/state/log directories and IPv4 forwarding control. Generated/user keys never enter the package. Recovered public lab profile keys are installed mode 0640, readable only by root and the authorized helper group.

## Physical acceptance procedure

The 0.2.1 operator acceptance on CardputerZero exercised real radio/client traffic, native framebuffer and evdev input, interception, exports and all twelve profiles: 17 feasible checks passed. Concurrent two-station isolation is the sole waived proof because a second authorized client was unavailable; it remains unproven. Remote framebuffer/evdev testing does not establish mechanical key or optical LCD condition. Android/Burp export formats were verified without claiming application import tests. See the canonical repository at <https://github.com/GainSec/GITM-CardputorZero> for the complete public acceptance summary.

For another device, run in an isolated authorized lab and retain outputs. The installed ARM64 container smoke checks binaries, package imports, profiles, exports, bounds and process teardown; it has no physical wireless/display hardware.

1. Record `ip -d -json link show`, `iw list`, `iw dev`, `ip -json address show`, `systemctl status gainsec-gitm-helper.socket`. Confirm the selected WAN has carrier and the AP radio supports AP mode.
2. Save `cat /proc/sys/net/ipv4/ip_forward` and `sudo nft list ruleset` as baseline evidence. Run the read-only plan and verify no interfaces, rules, files or services change.
3. Start all four features from the native keyboard GUI. Read SSID/key, feature state, and exact evidence paths. Confirm physical display legibility, typing (including spaces), page switching, scrolling, live/lease/TLS log selection and export controls.
4. Connect two authorized clients. Confirm DHCP, DNS, Ethernet NAT, client isolation at layer two and layer three, and blocked IPv6 forwarding. Confirm a timestamp/MAC/IP event for each lease.
5. Exercise full-packet PCAP rotation with >8 MB traffic: `tcpdump -nn -r /var/lib/gainsec-gitm/users/$(id -u)/traffic.pcap -c 10`. Confirm the exact filename, bound, owner and 0600 mode.
6. Export local CA to Android/Burp, install it only on an authorized disposable client, request a controlled HTTPS endpoint over TCP, and verify the presented leaf chains to the exported CA. Repeat with an ephemeral user-supplied subordinate plus full parent chain. Confirm pinned clients reject interception; evaluate QUIC separately.
7. Inspect `sudo nft list table inet gainsec_gitm` and confirm only the owned AP/subnet TCP/443 redirect. Direct connections to AP TCP/8443 must be blocked. Confirm unrelated WAN services still work.
8. Terminate each owned worker using the exact persisted PID/start-time evidence, one at a time; verify watchdog teardown. Repeat for low disk reserve in a controlled filesystem. Confirm partial cleanup remains retryable and no foreign PID is signaled.
9. Stop from GUI and CLI, close the app, and test service shutdown. Compare forwarding/rules/interfaces to baseline, confirm no worker remains, and retain logs. Test upgrade/remove with an active session; package removal must first stop owned services. Preserve local evidence/keys intentionally or delete them as the operator.

Do not call the historical shell implementation on the device. The package invokes only the narrow Python helper and trusted fixed command arguments.
