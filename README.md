# GainSec GITM for CardputerZero

GITM operates an authorized WPA2 research AP with DHCP, DNS, physical Ethernet WAN and NAT. It provides selectable full-packet capture, live traffic metadata, SSLsplit interception with local or validated custom CAs, all twelve recovered eMudhra lab profiles, timestamped lease events, Android certificate preparation and Burp exports. All six native GUI pages and the CLI operate these implemented features.

[Installation](#installation) · [GUI and keyboard](#gui-and-keyboard) · [CLI operation](#cli-operation) · [CA and export workflows](#ca-and-export-workflows) · [All 12 eMudhra profiles](#all-12-emudhra-profiles) · [Evidence and safety](#evidence-and-safety) · [Physical validation](#physical-validation) · [Build and package verification](#build-and-package-verification)

## Installation

Install on an **arm64 Debian CardputerZero** with an AP-capable Wi-Fi radio and a linked physical Ethernet interface. On the validated C0, these interfaces are **`wlan0`** and **`eth0`**. Keep Ethernet connected for management throughout AP operation.

After copying the package into the current directory on the C0:

```sh
sudo apt install --reinstall ./gainsec-gitm_0.2.1-1_arm64.deb
sudo adduser "$USER" gainsec-gitm
sudo adduser "$USER" video
sudo adduser "$USER" input
```

`--reinstall` also refreshes an existing local artifact with the same package version. Log out and back in to apply group membership. `gainsec-gitm` grants access to the restricted helper socket; `video` and `input` allow native framebuffer/keyboard access. Open **GainSec GITM** in APPLaunch, or run:

```sh
gitm --version
systemctl status gainsec-gitm-helper.socket
gitm gui --backend system
```

APT installs the exact declared dependencies: Python 3.11+, python3-pygame, python3-cryptography, hostapd, dnsmasq-base, NetworkManager, nftables, iw, iproute2, systemd, adduser, SSLsplit, tcpdump and OpenSSL. The desktop entry is `/usr/share/APPLaunch/applications/gitm.desktop`; its launcher is `/usr/share/GITM/bin/gitm`. Installed manuals are `/usr/share/doc/gainsec-gitm/README.md` and `README.CardputerZero.md`; screenshots and profile assets are under `/usr/share/GITM/`.

### Release a connected Wi-Fi radio

The AP needs the selected radio available. When `wlan0` already has an active NetworkManager station connection, save its settings and disconnect it before preflight. Run this optional preparation and its matching restoration block in the **same shell**, over Ethernet:

```sh
GITM_STA_UUID=$(nmcli -g GENERAL.CON-UUID device show wlan0)
GITM_STA_AUTO=$(nmcli -g connection.autoconnect connection show uuid "$GITM_STA_UUID")
sudo nmcli connection modify uuid "$GITM_STA_UUID" connection.autoconnect no
sudo nmcli device disconnect wlan0
```

Skip this block if the radio is already disconnected. Select the actual AP/WAN interfaces and the appropriate regulatory country for another device.

## GUI and keyboard

The GUI renders RGB565 to `/dev/fb_lcd` and reads the internal C0 keyboard, including its Fn punctuation map. It leaves held Escape under APPLaunch's control.

| Page | Operation |
|---|---|
| **Overview** | Preflight, review AP/WAN/SSID/key and selected features, acknowledge authorized clients, start, view active state and stop. |
| **Settings** | Toggle PCAP/live/TLS/lease logging; set capture size, SSID, WPA2 key, country, subnet, resolver, AP/WAN interfaces, custom certificate/key/chain paths, CA profile and export directory. |
| **Traffic** | Read bounded live, lease or TLS connection metadata; cycle log kind and scroll rows. |
| **Evidence** | Read exact capture/log/certificate paths and wrapped export paths. |
| **Profiles** | Verify and select any of the twelve recovered profiles; the final row returns to local/custom CA mode. |
| **Exports** | Prepare Android certificates, Burp PKCS12/PEM, or both in the configured private directory. |

- **C / Enter:** select an action. On Overview: preflight → acknowledge authorization → start; select again while active to stop.
- **F / X**, **Left / Right**, or **Tab:** switch pages.
- **W / S** or **Up / Down:** select or scroll rows.
- In text entry, **Enter saves**, **Escape cancels**, and **Backspace deletes**. Spaces, navigation-letter aliases and C0 Fn punctuation remain editable text.
- **Z / short Escape:** return to Overview or preflight. **Held Escape:** return to APPLaunch; app exit stops its active session and restores networking.

Stop the session before changing settings. Lease events are selected for new operator configurations. The GUI's default export destination is `~/.local/share/gainsec-gitm/exports`.

Tracked screenshots are deterministic 320×170 simulator fixtures. Displayed SSIDs/keys and traffic rows are synthetic examples, with no device captures or live credentials. The six store views are [Review](screenshots/review.png), [Settings](screenshots/settings.png), [Active](screenshots/active.png), [Traffic](screenshots/traffic.png), [Profiles](screenshots/profiles.png) and [Exports](screenshots/exports.png).

## CLI operation

The following C0 example selects **all four runtime features** and generates a random SSID/WPA2 key in a private configuration file. It uses the validated interface names, an AP subnet of `192.168.77.0/24`, and an operator-selected upstream DNS resolver:

```sh
gitm preflight --backend system
gitm configure --backend system --config "$HOME/gitm-lab.json" \
  --ap-interface wlan0 --wan-interface eth0 --country US \
  --subnet 192.168.77.0/24 --resolver 1.1.1.1 \
  --dump --capture-mb 8 --live --strip --lease-events

gitm render-plan --backend system --config "$HOME/gitm-lab.json"
gitm start --backend system --config "$HOME/gitm-lab.json" --dry-run
```

`configure` writes a mode-0600 configuration without changing networking. Plans and dry runs validate the complete configuration and CA material without creating an AP, CA or evidence files. Plans include the WPA2 key: keep their output private. Optional `--ssid` and `--passphrase` override the generated credentials.

Choose either native operation using that configuration:

```sh
gitm gui --backend system --config "$HOME/gitm-lab.json"
```

Or CLI start, finite inspection and stop:

```sh
gitm start --backend system --config "$HOME/gitm-lab.json" --authorized
gitm status --backend system
gitm inspect --backend system --kind live --limit 20
gitm inspect --backend system --kind leases --limit 20
gitm inspect --backend system --kind tls --limit 20
tcpdump -nn -r "/var/lib/gainsec-gitm/users/$(id -u)/traffic.pcap" -c 10
gitm stop --backend system
```

`--capture` aliases `--dump`; `--tls` aliases `--strip`. Boolean feature flags also accept their `--no-…` forms. `--backend system` uses real hardware; `auto` selects the available backend. Help is available for every command:

```sh
gitm --help
gitm configure --help
gitm start --help
gitm export --help
```

For off-device development, `--backend sim` exercises configuration, plans, CA/profile operations, exports and UI without creating an AP, hardware worker processes or capture files. Responses identify simulation. The GUI also accepts `--screenshot PATH --demo-state STATE` for deterministic 320×170 fixture rendering.

After stopping, restore the saved station connection if you used the preparation block:

```sh
sudo nmcli connection modify uuid "$GITM_STA_UUID" connection.autoconnect "$GITM_STA_AUTO"
sudo nmcli connection up uuid "$GITM_STA_UUID" ifname wlan0
```

GITM itself restores its previous forwarding value and removes its owned AP/rules; the optional NetworkManager commands restore the station connection the operator explicitly disconnected.

## CA and export workflows

Use **one CA selection per session**. Stop before switching CA/configuration. Enable TLS with `--strip`/`--tls`; custom CA paths or `--emudhra` also select TLS automatically. Status and export responses report exact evidence/artifact paths; exports also return the certificate fingerprint.

### Local CA

With the main configuration above and no custom/profile selection, the helper generates or reuses the requesting user's local CA in `/var/lib/gainsec-gitm/ca/<uid>/`. Prepare exports before or after starting the AP:

```sh
gitm export --backend system --config "$HOME/gitm-lab.json" \
  --android --burp --output-dir "$HOME/gitm-exports"
```

Give only the public `ca.crt` to an authorized client using its approved lab trust workflow. Request a controlled HTTPS origin over TCP; the trusted client should accept the intercepted leaf. A negative control without the lab CA should reject it. Per-request trust, as used in acceptance, avoids changing the client's system trust store.

### Custom subordinate CA and complete chain

Place the supplied PEM certificate, matching unencrypted private key and complete issuer chain in `~/lab-ca/` before running this example. Protect the key and input directory. `parents.pem` must complete the trust path to the self-signed root. `--ca-chain` may be omitted only when the supplied certificate already forms a complete verifiable path by itself.

```sh
gitm configure --backend system --config "$HOME/gitm-custom.json" \
  --ap-interface wlan0 --wan-interface eth0 --country US \
  --dump --capture-mb 8 --live --strip --lease-events \
  --ca-cert "$HOME/lab-ca/subordinate.crt" \
  --ca-key "$HOME/lab-ca/subordinate.key" \
  --ca-chain "$HOME/lab-ca/parents.pem"
gitm start --backend system --config "$HOME/gitm-custom.json" --dry-run
gitm start --backend system --config "$HOME/gitm-custom.json" --authorized
gitm export --backend system --config "$HOME/gitm-custom.json" \
  --android --burp --output-dir "$HOME/gitm-custom-exports"
gitm stop --backend system
```

Validation checks strict PEM structure, certificate/key match, validity, `CA:TRUE`, `keyCertSign`, issuer/signature links, path-length constraints, supported critical extensions and a complete verified chain. Malformed/trailing PEM, wrong keys and incomplete chains fail before network mutation or export destination creation. The unprivileged frontend reads inputs and passes validated material over the private helper socket; root never opens caller-selected CA paths. Custom material and a bundled profile are mutually exclusive.

### Android and Burp artifacts

| Artifact | Purpose |
|---|---|
| `ca.crt` | Public signing certificate for the selected CA. |
| `xxxxxxxx.0` | Android certificate named with OpenSSL `subject_hash_old`; use the exact returned filename. |
| `mitm.p12` | PKCS12 containing the selected private key, certificate and supplied parent chain; empty import password. |
| `mitm_combined.pem` | Certificate + private key + parent chain for PEM import workflows. |

`--android` or `--burp` can be selected independently. Every export file is **0600**, written atomically inside a **0700** directory. Treat PKCS12/combined PEM as signing secrets. Use the target Android/Burp application's authorized import workflow; export preparation itself changes no client trust store. The acceptance verified formats, hashes, chains and permissions, without claiming handset or Burp GUI import testing.

## All 12 eMudhra profiles

All profiles are included and usable from GUI and CLI:

| Family | DV | OV | EV |
|---|---|---|---|
| G3b / AAA | `dv-g3b-aaa` | `ov-g3b-aaa` | `ev-g3b-aaa` |
| G3b / emSign | `dv-g3b-emsign` | `ov-g3b-emsign` | `ev-g3b-emsign` |
| G3c / AAA | `dv-g3c-aaa` | `ov-g3c-aaa` | `ev-g3c-aaa` |
| G3c / emSign | `dv-g3c-emsign` | `ov-g3c-emsign` | `ev-g3c-emsign` |

```sh
gitm profiles
gitm profile-info dv-g3b-emsign
gitm verify-profile dv-g3b-aaa
gitm start --backend system --config "$HOME/gitm-lab.json" \
  --emudhra dv-g3b-aaa --authorized
gitm export --backend system --config "$HOME/gitm-lab.json" \
  --emudhra dv-g3b-aaa --android --burp \
  --output-dir "$HOME/gitm-profile-exports"
gitm stop --backend system
```

Use the **same profile** for interception and export. Bare `--emudhra` selects `dv-g3b-aaa`. Profile info returns provenance, revocation details, fingerprints and asset paths; verification checks original SHA256 pins, matching key and trust path before use.

The exact twelve profile directories match validated source commit `ae20080ca2e4cfc6d0fcd399ea09c7068c88c15e`; `profiles/emudhra/provenance.json` pins their Git blobs and SHA256 values. Public upstream certificate/key references are retained in each manifest. Certificates/keys were not fabricated or regenerated. AAA profiles chain directly to `AAA Certificate Services`; emSign profiles include the additional parent chain. Offline trust anchors are retained for deterministic verification.

These are the original **revoked lab certificates and historically public reconstructed keys**, intended for authorized isolated stale-trust testing. They do not grant general public trust. All twelve passed controlled Mac/AP TLS handshakes with explicit per-request pinned lab anchors; that result does not claim acceptance by a patched client's normal trust/revocation policy. The only package key-scan exception is this exact pinned corpus, installed mode **0640** for root and `gainsec-gitm`.

## Evidence and safety

`start`/`status` return fixed private paths under `/var/lib/gainsec-gitm/users/<uid>/`:

| Path | Data and bound |
|---|---|
| `traffic.pcap` | Full-packet rotating PCAP; **1–64 decimal MB**, plus at most one packet of rotation overhead. |
| `live.jsonl` | Sanitized timestamp/address/port/protocol/length metadata; **256 KiB**. |
| `leases.jsonl` | Timestamp, MAC and assigned IP events; **256 KiB**. |
| `tls.log` | SSLsplit connection metadata; **512 KiB** kernel file limit. |
| `ca.crt` | Public certificate for the session's selected signing CA. |

Evidence files are requester-owned **0600** in fixed helper-owned directories. **A new session replaces its selected evidence files**: copy them to private storage before starting another session. Inspection returns a finite sanitized snapshot, never active packet content. SSLsplit writes connection metadata; decrypted payload logs and TLS master-key logs are not enabled.

- The group-restricted helper socket is `/run/gainsec-gitm/helper.sock`, **0660**. Privileged imports and command paths are package-owned; no broad sudoers grant is installed.
- The helper records PID, kernel start time and executable identity for every daemon/worker, including SSLsplit's actual listener child. It checks liveness, performs bounded termination, retries partial teardown and uses its systemd cgroup as a cleanup fallback. Startup has a separate finite budget for C0 initialization.
- Only the owned **`gitm-ap`** interface and **`inet gainsec_gitm`** table are created/removed. No global firewall flush or unowned-PID cleanup occurs. Other networking and baseline IPv4 forwarding are preserved.
- TLS redirect is scoped to **IPv4 TCP/443** arriving on the owned AP subnet/interface. SSLsplit listens at the AP gateway's **TCP/8443**; direct access is blocked. AP IPv6 forwarding is blocked. QUIC and certificate-pinned clients are not transparent TCP TLS interception targets.
- Startup reserves the capture budget plus **16 MB** free space; the runtime watchdog maintains the **16 MB** reserve. Worker loss or low storage tears down the session. TLS log exhaustion stops SSLsplit and triggers that same cleanup. `gitm stop` clears the resulting blocked status after successful teardown.
- Planned signal shutdown, socket reactivation, native app exit, package upgrade and removal stop owned resources. Local CA/private exports/evidence remain for intentional operator retention; they are never embedded in the package. Only assess clients and traffic you are authorized to test.

## Physical validation

Operator acceptance on **CardputerZero**, **2026-11-18**, used a controlled Wi-Fi client and retained wired Ethernet management throughout. All **17 feasible device checks passed**:

| Area | Observed result |
|---|---|
| APPLaunch / native UI | Real framebuffer/evdev operation, C0 Fn punctuation, text/navigation, all feature controls, traffic/evidence/profile/export pages, start/stop and graceful held-Escape return from an active AP. |
| Network / leases | Real DHCP, UDP/TCP DNS, benign HTTP through Ethernet NAT, timestamp/MAC/IP lease events; AP-local SSH and direct 8443 rejection. |
| Capture / inspection | Controlled 4 MiB transfers caused four PCAP wraps; latest maximum 1,000,348 bytes for a 1 MB budget, requester ownership/mode 0600; readable PCAP and bounded live/lease/TLS views. |
| CA / profiles / exports | Local/custom full-chain TLS positive and negative controls; malformed CA validation before mutation; all 12 exact profile client handshakes; Android/PKCS12/PEM format, parent-chain and permission checks. |
| Failure / lifecycle | Individual loss of all seven owned workers, isolated 24 MiB low-storage test, helper signal/reactivation, all-feature active upgrade/removal/reinstall and active-app exit restored the baseline. |
| Final restoration | No owned AP/workers/rules or test service/timer/mount remained; forwarding returned to its baseline; Ethernet management was preserved; original Wi-Fi/autoconnect and controlled-client state were restored; test SSIDs were forgotten. |

**Sole waived proof: concurrent two-station isolation.** The operator confirms no second authorized Wi-Fi client is available, so this proof is **externally blocked and waived for this acceptance**, not recorded as a pass. Hostapd `ap_isolate=1`, owned nft policy and AP-local rejection were checked; they do not substitute for two independent associated stations.

Framebuffer/evdev evidence establishes the native functional path; it does not claim mechanical-key or optical-panel inspection. Export preparation/format validation is distinct from Android/Burp application import testing. Neither changes the scope of the sole waived two-station proof.

The public device procedure is `docs/CARDPUTERZERO.md` in the checkout and `README.CardputerZero.md` beside this installed manual. Private device captures and operator records are excluded from this release. The rebuilt public package is verified locally against the accepted runtime source; this release preparation does not claim a new physical device run.

## Build and package verification

Canonical repository: <https://github.com/GainSec/GITM-CardputorZero>. Clone on a development host with Python, uv and Docker:

```sh
git clone https://github.com/GainSec/GITM-CardputorZero.git
cd GITM-CardputorZero
```

From the repository checkout:

```sh
uv sync --extra test
.venv/bin/python -m pytest -W error -q
.venv/bin/python -m compileall -q src tools
bash -n tools/build_deb.sh tools/smoke_arm64.sh gitm.sh tests/test_emudhra_profiles.sh
bash tests/test_emudhra_profiles.sh
PYTHON_BIN=.venv/bin/python tools/build_deb.sh
tools/smoke_arm64.sh
```

The package is written to `dist/gainsec-gitm_0.2.1-1_arm64.deb`. The installed ARM64 gate compares the embedded README/assets to source bytes and exercises real SSLsplit, capture rotation/readback, worker ownership/teardown, profiles, exports, CLI and native rendering. The warnings-as-errors host and installed ARM64 suites each pass **252 tests**. Container integration and real-device validation are separately recorded.

The source/package audit checks every payload path, exact module/document/asset bytes, dependency policy, corpus provenance, and secret/key/capture exclusion. Generated/user/test CA keys, PCAPs and private exports are excluded from the Debian payload. The historical upstream `gitm.sh` remains source provenance; the native application neither invokes nor packages it.

Release package size, SHA-256 and public verification results are recorded in `release-manifest.json`, outside the package. To audit an extracted package, run `.venv/bin/python tools/audit_payload.py EXTRACTED_ROOT`. The audit permits exactly the twelve pinned profile keys and rejects generated credentials, captures and private development data.

## Cleanup and uninstall

Stop the owned session before uninstalling:

```sh
gitm stop --backend system
sudo apt remove gainsec-gitm
```

Removal asks the helper to clean up owned resources and fails if cleanup cannot be proven. Retain the helper state and inspect service logs if teardown fails; do not delete ownership records to bypass recovery. After a successful stop, `sudo apt purge gainsec-gitm` removes package configuration. Generated CA keys, private exports and evidence are retained intentionally: review and remove them from their reported paths only when no longer needed. Remove any lab trust installed on disposable clients through their approved trust-management workflow. Group membership is retained for administrator review.

Contribute at the [canonical GitHub repository](https://github.com/GainSec/GITM-CardputorZero) following [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities through [SECURITY.md](SECURITY.md). MIT license: [LICENSE](LICENSE).
