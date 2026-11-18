#!/usr/bin/env python3
"""Create a deterministic Debian package staging tree."""

from pathlib import Path
import shutil


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2.1"
DEBIAN_VERSION = "0.2.1-1"
PACKAGE_FILENAME = f"gainsec-gitm_{DEBIAN_VERSION}_arm64.deb"
SYSTEM_ROOTS = tuple(Path(item) for item in ("/bin", "/etc", "/lib", "/lib64", "/sbin", "/usr", "/var"))


def _copy(source: Path, destination: Path, mode: int = 0o644) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    destination.chmod(mode)


def _staging_marker(destination: Path) -> Path:
    return destination.parent / f".{destination.name}.gainsec-gitm-staging"


def _validate_staging_destination(destination: Path) -> None:
    broad_targets = {Path("/"), Path.home(), ROOT, *ROOT.parents}
    under_system_root = any(destination == root or root in destination.parents for root in SYSTEM_ROOTS)
    insufficiently_specific = destination.parent == Path("/")
    if destination in broad_targets or under_system_root or insufficiently_specific:
        raise ValueError(f"unsafe staging destination: {destination}")
    package_owned_default = destination == ROOT / "build/package"
    if destination.exists() and not package_owned_default and not _staging_marker(destination).is_file():
        raise ValueError(f"unowned staging destination: {destination}")


def stage_package(destination: Path) -> Path:
    destination = destination.resolve()
    _validate_staging_destination(destination)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, mode=0o755)
    _staging_marker(destination).write_text(str(destination) + "\n", encoding="utf-8")

    _copy(ROOT / "packaging/debian/control", destination / "DEBIAN/control")
    _copy(ROOT / "packaging/debian/postinst", destination / "DEBIAN/postinst", 0o755)
    _copy(ROOT / "packaging/debian/prerm", destination / "DEBIAN/prerm", 0o755)
    _copy(ROOT / "packaging/debian/postrm", destination / "DEBIAN/postrm", 0o755)
    _copy(ROOT / "packaging/wrappers/gitm", destination / "usr/bin/gitm", 0o755)
    _copy(ROOT / "packaging/wrappers/gitm-applaunch", destination / "usr/share/GITM/bin/gitm", 0o755)
    _copy(ROOT / "packaging/wrappers/gainsec-gitm-helper", destination / "usr/libexec/gainsec-gitm-helper", 0o755)
    _copy(ROOT / "packaging/gitm.desktop", destination / "usr/share/APPLaunch/applications/gitm.desktop")
    _copy(ROOT / "assets/gitm.png", destination / "usr/share/APPLaunch/share/images/gitm.png")
    _copy(ROOT / "assets/gitm.png", destination / "usr/share/GITM/assets/gitm.png")
    _copy(ROOT / "assets/gitm-icon-256.png", destination / "usr/share/GITM/assets/gitm-icon-256.png")
    _copy(ROOT / "packaging/systemd/gainsec-gitm-helper.socket", destination / "lib/systemd/system/gainsec-gitm-helper.socket")
    _copy(ROOT / "packaging/systemd/gainsec-gitm-helper.service", destination / "lib/systemd/system/gainsec-gitm-helper.service")
    _copy(ROOT / "README.md", destination / "usr/share/doc/gainsec-gitm/README.md")
    _copy(ROOT / "app-builder.json", destination / "usr/share/GITM/app-builder.json")
    for image in (ROOT / "screenshots").glob("*.png"):
        _copy(image, destination / "usr/share/GITM/screenshots" / image.name)
    for asset in (ROOT / "profiles/emudhra").rglob("*"):
        if asset.is_file():
            _copy(asset, destination / "usr/share/GITM/profiles/emudhra" / asset.relative_to(ROOT / "profiles/emudhra"), 0o640 if asset.suffix == ".key" else 0o644)
    _copy(ROOT / "LICENSE", destination / "usr/share/doc/gainsec-gitm/LICENSE")
    _copy(ROOT / "LICENSE", destination / "usr/share/doc/gainsec-gitm/copyright")
    _copy(ROOT / "docs/CARDPUTERZERO.md", destination / "usr/share/doc/gainsec-gitm/README.CardputerZero.md")

    package_source = ROOT / "src/gitm"
    package_target = destination / "usr/share/GITM/gitm"
    shutil.copytree(
        package_source,
        package_target,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    for path in package_target.rglob("*"):
        if path.is_file():
            path.chmod(0o644)
        elif path.is_dir():
            path.chmod(0o755)
    return destination


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path, nargs="?", default=ROOT / "build/package")
    args = parser.parse_args()
    print(stage_package(args.destination))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
