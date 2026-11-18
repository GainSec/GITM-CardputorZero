import json
from pathlib import Path
import re
import tomllib

import gitm

from tools.stage_package import DEBIAN_VERSION, PACKAGE_FILENAME, VERSION


ROOT = Path(__file__).parents[1]


def test_version_is_consistent_everywhere():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    app_builder = json.loads((ROOT / "app-builder.json").read_text())
    assert VERSION == "0.2.1"
    assert gitm.__version__ == VERSION
    assert project["project"]["version"] == VERSION
    assert app_builder["version"] == VERSION
    assert DEBIAN_VERSION == "0.2.1-1"
    assert PACKAGE_FILENAME == "gainsec-gitm_0.2.1-1_arm64.deb"


def test_ui_displays_canonical_version():
    source = (ROOT / "src/gitm/gui.py").read_text()
    assert "0.2.1" in source
