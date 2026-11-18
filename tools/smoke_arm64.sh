#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PACKAGE_PATH="$ROOT_DIR/dist/gainsec-gitm_0.2.1-1_arm64.deb"
SCREENSHOT_DIR="$ROOT_DIR/dist/screenshots"

mkdir -p "$SCREENSHOT_DIR"
docker build --platform linux/arm64 -t gainsec-gitm-arm64-qa:bookworm - < "$ROOT_DIR/tools/qa-arm64.Dockerfile"
docker run --rm --platform linux/arm64 --cap-add NET_ADMIN --cap-add NET_RAW \
    -e DEBIAN_FRONTEND=noninteractive -e SDL_VIDEODRIVER=dummy -e SDL_AUDIODRIVER=dummy \
    -e PYGAME_HIDE_SUPPORT_PROMPT=1 -e PYTHONPATH=/usr/share/GITM -e PYTHONDONTWRITEBYTECODE=1 \
    -v "$PACKAGE_PATH:/tmp/gainsec-gitm.deb:ro" \
    -v "$SCREENSHOT_DIR:/out" -v "$ROOT_DIR:/source:ro" \
    gainsec-gitm-arm64-qa:bookworm bash -euc '
        apt-get install -y -qq /tmp/gainsec-gitm.deb
        useradd -m -G gainsec-gitm gitmqa
        gitm status --backend sim >/tmp/status.json
        gitm preflight --backend sim >/tmp/preflight.json
        gitm render-plan --backend sim --dump --live --strip --lease-events >/tmp/plan.json
        gitm start --backend sim --dump --strip --dry-run >/tmp/dry-run.json
        gitm export --backend sim --android --burp --output-dir /tmp/gitm-exports >/tmp/exports.json
        for state in PREFLIGHT REVIEW STARTING ACTIVE STOPPING ERROR; do
            lower=$(printf "%s" "$state" | tr "[:upper:]" "[:lower:]")
            gitm gui --backend sim --screenshot "/out/${lower}.png" --demo-state "$state"
        done
        python3 /source/tools/installed_smoke.py
        cd /source
        GITM_TEST_INSTALLED=1 python3 -m pytest -W error -q -p no:cacheprovider
        python3 /source/tools/check_readme.py /source/README.md
        python3 - <<"PY"
import json
from pathlib import Path
import pygame
assert json.loads(Path("/tmp/status.json").read_text())["simulated"]
assert json.loads(Path("/tmp/preflight.json").read_text())["ok"]
plan = json.loads(Path("/tmp/plan.json").read_text())
assert plan["capture_enabled"] and plan["tls_interception_enabled"]
for path in Path("/out").glob("*.png"):
    assert pygame.image.load(path).get_size() == (320, 170), path
assert len(list(Path("/out").glob("*.png"))) == 6
print("PASS installed CLI feature plans/exports and six native screenshots")
PY
    '
