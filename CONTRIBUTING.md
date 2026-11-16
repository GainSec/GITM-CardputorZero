# Contributing

Contributions are welcome through pull requests to <https://github.com/GainSec/GITM-CardputorZero>.

## Before submitting

1. Keep the `v0.1.0` scope honest: authorized AP, DHCP/DNS forwarding, NAT, and owned rollback. Do not describe TLS interception or packet capture as available.
2. Add or update tests for every safety or lifecycle change.
3. Run the warnings-as-errors pytest suite, compileall, shell syntax checks, Debian package build, and ARM64 installed-package smoke test documented in the README.
4. Confirm `git diff --check` passes and scan the candidate and package for credentials, private keys/certificates, captures, private endpoints, and personal paths.
5. Keep mutations structured, fail-closed, package-owned, and reversible. Do not add shell interpolation, broad firewall flushes, global process kills, or sudoers bypasses.
6. Update public metadata and documentation when behavior, dependencies, versions, package contents, screenshots, or URLs change.

By contributing, you agree that your contribution is provided under the repository’s MIT license.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
