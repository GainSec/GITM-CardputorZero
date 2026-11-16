#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PACKAGE_PATH="$ROOT_DIR/dist/gainsec-gitm_0.1.0-1_arm64.deb"
SCREENSHOT_DIR="$ROOT_DIR/dist/screenshots"

mkdir -p "$SCREENSHOT_DIR"
docker run --rm --platform linux/arm64 \
    -e DEBIAN_FRONTEND=noninteractive \
    -e SDL_VIDEODRIVER=dummy \
    -e SDL_AUDIODRIVER=dummy \
    -v "$PACKAGE_PATH:/tmp/gainsec-gitm.deb:ro" \
    -v "$SCREENSHOT_DIR:/out" \
    debian:bookworm-slim bash -euc '
        apt-get update -qq
        apt-get install -y -qq /tmp/gainsec-gitm.deb
        gitm status --backend sim >/tmp/status.json
        gitm preflight --backend sim >/tmp/preflight.json
        gitm render-plan --backend sim >/tmp/plan.json
        for state in PREFLIGHT REVIEW STARTING ACTIVE STOPPING ERROR; do
            lower=$(printf "%s" "$state" | tr "[:upper:]" "[:lower:]")
            gitm gui --backend sim --screenshot "/out/${lower}.png" --demo-state "$state"
        done
        python3 - <<"PY"
import json
from pathlib import Path
import pygame
assert json.loads(Path("/tmp/status.json").read_text())["backend"] == "sim"
assert json.loads(Path("/tmp/preflight.json").read_text())["ok"] is True
assert json.loads(Path("/tmp/plan.json").read_text())["nft_table"] == "gainsec_gitm"
for path in Path("/out").glob("*.png"):
    assert pygame.image.load(path).get_size() == (320, 170), path
assert len(list(Path("/out").glob("*.png"))) == 6
print("installed smoke: status/preflight/render-plan + 6 screenshots PASS")
PY
    '
