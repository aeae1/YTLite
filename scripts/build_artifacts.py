#!/usr/bin/env python3
"""Record and verify the exact files passed between build and packaging jobs."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile

from free_ytplus import PATCHES, LIBRARY_PATH, BUNDLE_PATH, unpack, account_string
from supply_chain import LOCK

DEBS = ("ytplus.deb", "youpip.deb", "ytuhd.deb", "ryd.deb", "ytabc.deb", "ygs.deb", "yq.deb", "ytvo.deb", "demc.deb")
SAFARI = "OpenYouTubeSafariExtension.appex"
REPORT = "free-build-report.json"


def digest(path):
    with Path(path).open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def validate_deb(path):
    """The packager never needs maintainer scripts, links, or privileged files."""
    for option in ("--fsys-tarfile", "--ctrl-tarfile"):
        data = subprocess.run(["dpkg-deb", option, str(path)], check=True, stdout=subprocess.PIPE).stdout
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            for member in archive:
                p = PurePosixPath(member.name)
                if (p.is_absolute() or ".." in p.parts or "\\" in member.name
                        or not (member.isfile() or member.isdir()) or member.mode & 0o6000):
                    raise ValueError("Unsafe DEB archive member")
                if member.isfile() and option == "--ctrl-tarfile" and str(p) not in ("control", "md5sums"):
                    raise ValueError("DEB contains an unreviewed maintainer script or control file")


def artifact_files(root):
    root = Path(root)
    unknown = {p.name for p in root.glob("*.deb")} - set(DEBS)
    if unknown:
        raise ValueError("Unexpected DEB files in the build artifact directory")
    files = [root / p for p in (*DEBS, REPORT) if (root / p).is_file()]
    extension = root / SAFARI
    if extension.exists():
        files.extend(p for p in extension.rglob("*") if p.is_file() or p.is_symlink())
    if not (root / DEBS[0]).is_file() or not (root / REPORT).is_file():
        raise ValueError("Core package or its build report is missing")
    if any(p.is_symlink() for p in files) or extension.is_symlink():
        raise ValueError("Build artifacts cannot contain symbolic links")
    return sorted(files)


def write_manifest(root, output):
    root = Path(root)
    files = artifact_files(root)
    for path in files:
        if path.suffix == ".deb":
            validate_deb(path)
    report = json.loads((root / REPORT).read_text())
    if report["package_sha256"] != digest(root / "ytplus.deb"):
        raise ValueError("Core package does not match its build report")
    document = {"schema": 1, "dependencies_lock_sha256": digest(LOCK),
                "files": {str(p.relative_to(root)): digest(p) for p in files}}
    Path(output).write_text(json.dumps(document, indent=2) + "\n")


def verify_manifest(root, manifest):
    root = Path(root)
    data = json.loads(Path(manifest).read_text())
    if data.get("schema") != 1 or data.get("dependencies_lock_sha256") != digest(LOCK):
        raise ValueError("Build artifacts came from a different dependency lock")
    actual = {str(p.relative_to(root)): digest(p) for p in artifact_files(root)}
    if actual != data.get("files"):
        raise ValueError("Build artifacts are missing, unexpected, or have changed")
    for name in DEBS:
        if (root / name).exists():
            validate_deb(root / name)
    report = json.loads((root / REPORT).read_text())
    if report["package_sha256"] != actual["ytplus.deb"]:
        raise ValueError("Core package does not match its build report")
    return [root / name for name in DEBS if (root / name).exists()] + ([root / SAFARI] if (root / SAFARI).exists() else [])


def verify_core(package, destination):
    import plistlib
    unpack(Path(package), Path(destination))
    root = Path(destination)
    raw = (root / LIBRARY_PATH).read_bytes()
    for name, offset, _, replacement in PATCHES:
        if raw[offset:offset + len(replacement)] != replacement:
            raise ValueError(f"Unexpected core instructions: {name}")
    locales = list((root / BUNDLE_PATH).glob("*.lproj/Localizable.strings"))
    if len(locales) < 13:
        raise ValueError("Core localizations are missing")
    for path in locales:
        data = path.read_bytes()
        try:
            keys = plistlib.loads(data)
        except plistlib.InvalidFileException:
            keys = re.findall(r'^\s*"([^"\\]+)"\s*=', data.decode("utf-8-sig"), re.MULTILINE)
        if any(account_string(key) for key in keys):
            raise ValueError("Account localization cleanup is incomplete")
    if "Version: 6.0-free1" not in (root / "DEBIAN/control").read_text().splitlines():
        raise ValueError("Unexpected core package version")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("write", "verify", "core"))
    parser.add_argument("root", type=Path)
    parser.add_argument("file", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "core":
            verify_core(args.root, args.file)
        elif args.mode == "write":
            write_manifest(args.root, args.file)
        else:
            verify_manifest(args.root, args.file)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError, tarfile.TarError) as error:
        parser.exit(1, f"Artifact validation failed: {error}\n")


if __name__ == "__main__":
    main()
