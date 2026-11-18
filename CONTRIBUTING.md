# Contributing

Contributions are welcome through pull requests to <https://github.com/GainSec/GITM-CardputorZero>.

## Before submitting

1. Preserve the `0.2.1` suite: AP/DHCP/DNS/NAT, bounded capture and inspection, local/custom/profile TLS, lease events, Android/Burp exports, native GUI/keyboard, CLI and owned rollback. Document physical acceptance limits accurately.
2. Add or update tests for every safety or lifecycle change.
3. Run the warnings-as-errors pytest suite, compileall, shell syntax checks, Debian package build, and ARM64 installed-package smoke test documented in the README.
4. Confirm `git diff --check` passes and scan the candidate and package for credentials, generated/user private keys, captures, private endpoints, and personal paths.
5. Keep mutations structured, fail-closed, package-owned, and reversible. Do not add shell interpolation, broad firewall flushes, global process kills, or sudoers bypasses.
6. Allow only the twelve documented, byte-pinned eMudhra lab profile keys; never add generated credentials or private development evidence.
7. Update public metadata and documentation when behavior, dependencies, versions, package contents, screenshots, or URLs change.

By contributing, you agree that your contribution is provided under the repository’s MIT license.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
