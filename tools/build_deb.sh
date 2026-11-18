#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PYTHON_BIN=${PYTHON_BIN:-python3}

cd "$ROOT_DIR"
mkdir -p build dist
"$PYTHON_BIN" tools/stage_package.py build/package >/dev/null
docker run --rm --platform linux/arm64 \
    -v "$ROOT_DIR:/work" -w /work debian:bookworm-slim \
    dpkg-deb --build --root-owner-group build/package dist/gainsec-gitm_0.2.1-1_arm64.deb
