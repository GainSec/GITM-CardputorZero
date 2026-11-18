import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if not os.environ.get("GITM_TEST_INSTALLED") and str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("SDL_VIDEODRIVER", "dummy")
os.environ.setdefault("SDL_AUDIODRIVER", "dummy")

if os.environ.get("GITM_TEST_INSTALLED"):
    import gitm
    assert Path(gitm.__file__).is_relative_to("/usr/share/GITM"), gitm.__file__
