# Bundled eMudhra Lab Profiles

These profiles contain the publicly reconstructed private keys and revoked intermediate CA certificates from the October 2026 eMudhra/emSign incident. They are included only for authorized, isolated compatibility testing of devices you own or are permitted to assess.

Each profile contains `ca.crt`, `ca.key`, `trust-anchor.pem`, and `manifest.json`. Profiles chaining through `emSign Root TLS CA - G3` also contain `chain.pem`, because that issuer is itself subordinate to `emSign ECC Root CA - G3`. The `aaa` profiles chain directly to the device's pre-existing `AAA Certificate Services` trust anchor and therefore do not need an extra chain file. `trust-anchor.pem` is retained for deterministic offline testing and is not passed to SSLsplit.

Use `gitm profiles`, `gitm profile-info NAME`, and `gitm verify-profile NAME` before interception. Select `--emudhra NAME` with the native CLI or choose a profile in the GUI. The historical `gitm.sh` is retained only for deterministic regression tests.

Sources are pinned in each manifest. All bundled certificates are revoked. A modern or correctly patched client should reject them.

All twelve profile directories are byte-identical to validated source commit `ae20080ca2e4cfc6d0fcd399ea09c7068c88c15e`. `provenance.json` records public pins; each profile manifest retains public upstream references. These twelve documented `ca.key` files are the only private-key files allowed in the public source and Debian payload. No generated or user CA key is included.
