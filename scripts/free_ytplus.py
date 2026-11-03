#!/usr/bin/env python3
"""Create a version-pinned, offline YTPlus 6.0 package.

The upstream repository does not publish the current implementation. This
patch therefore accepts exactly one audited arm64 release, checks its full
digest, and changes four entry points. It never runs the downloaded library.
"""

import argparse
import hashlib
import io
import json
from pathlib import Path
import plistlib
import re
import shutil
import struct
import subprocess
import tarfile
import tempfile

VERSION = "6.0"
PACKAGE_SHA256 = "9822234413eeb085faec8f77864360156900bd62f281294b38b05e066777a55d"
LIBRARY_SHA256 = "a697e0397db6df0a223fc3e7080f6b32f1d023ba1a34340140d4c600db6df7c2"
LIBRARY_PATH = Path("Library/MobileSubstrate/DynamicLibraries/YTLite.dylib")
BUNDLE_PATH = Path("Library/Application Support/YTLite.bundle")
RET = 0xD65F03C0


def words(*instructions):
    return struct.pack("<" + "I" * len(instructions), *instructions)


def adrp(register, pc, address):
    pages = ((address & ~0xFFF) - (pc & ~0xFFF)) >> 12
    if not -(1 << 20) <= pages < (1 << 20):
        raise ValueError("ADRP target is out of range")
    pages &= (1 << 21) - 1
    return 0x90000000 | ((pages & 3) << 29) | ((pages >> 2) << 5) | register


def branch_link(pc, address):
    displacement = address - pc
    if displacement % 4 or not -(1 << 27) <= displacement < (1 << 27):
        raise ValueError("BL target is out of range")
    return 0x94000000 | ((displacement >> 2) & 0x3FFFFFF)


def empty_section():
    """Return a valid empty DVNSection, preserving the caller's object contract."""
    base = 0x34B160
    return words(
        0xA9BF7BFD,  # stp x29,x30,[sp,#-16]!
        0x910003FD,  # mov x29,sp
        adrp(8, base + 8, 0x2255530),
        0xF9400000 | ((0x530 // 8) << 10) | (8 << 5),  # DVNSection class
        adrp(8, base + 16, 0x22532E8),
        0xF9400000 | ((0x2E8 // 8) << 10) | (8 << 5) | 1,  # sectionWithIdentifier:
        0xAA1F03E2,  # mov x2,xzr (no account identifier)
        branch_link(base + 28, 0x17A47F4),  # objc_msgSend
        0xA8C17BFD,  # ldp x29,x30,[sp],#16
        RET,
    )


# The audited __TEXT segment has identical virtual addresses and file offsets.
# A whole-file digest check below makes those offsets specific to this release.
PATCHES = (
    ("initialize feature hooks immediately", 0xBF314,
     bytes.fromhex("ffc303d1f6570ca9"), words(0xF9400808, 0xD61F0100)),
    ("allow preferences without account activation", 0xC24BC,
     bytes.fromhex("ff8306d1fc6f14a9"), words(0x52800020, RET)),
    ("disable account service startup", 0xC804C,
     bytes.fromhex("ff0302d1"), words(RET)),
    ("remove account and subscription settings", 0x34B160,
     bytes.fromhex("f85fbca9f65701a9f44f02a9fd7b03a9fdc30091ff8300d1f30302aaf40300aa68fe009008811291"),
     empty_section()),
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def patch_binary(data):
    if digest(data) != LIBRARY_SHA256:
        raise ValueError("Unsupported library: expected the original YTPlus 6.0 arm64 release")
    result = bytearray(data)
    for name, offset, before, after in PATCHES:
        if len(before) != len(after) or result[offset:offset + len(before)] != before:
            raise ValueError(f"Unexpected instructions at {name}")
        result[offset:offset + len(after)] = after
    return bytes(result)


def account_string(key):
    return key.startswith("Access.") or key in {"FeaturesNotActivated", "LogIn", "LogOut"}


def clean_localizations(bundle):
    changed = 0
    for path in sorted(bundle.glob("*.lproj/Localizable.strings")):
        raw = path.read_bytes()
        try:
            values = plistlib.loads(raw)
        except plistlib.InvalidFileException:
            # Repository-provided translations use Apple's text .strings format.
            text = raw.decode("utf-8-sig")
            lines = []
            for line in text.splitlines(keepends=True):
                match = re.match(r'\s*"([^"\\]+)"\s*=', line)
                if not match or not account_string(match.group(1)):
                    lines.append(line)
            updated = "".join(lines).encode("utf-8")
        else:
            updated = plistlib.dumps(
                {k: v for k, v in values.items() if not account_string(k)},
                fmt=plistlib.FMT_BINARY, sort_keys=False,
            )
        if updated != raw:
            path.write_bytes(updated)
            changed += 1
    return changed


def unpack(package, destination):
    for option, target in (("--fsys-tarfile", destination),
                           ("--ctrl-tarfile", destination / "DEBIAN")):
        target.mkdir(parents=True, exist_ok=True)
        archive = subprocess.run(["dpkg-deb", option, str(package)], check=True,
                                 stdout=subprocess.PIPE).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(target, filter="data")


def make_package(package, report_path, localizations=None):
    package = package.resolve()
    if digest(package.read_bytes()) != PACKAGE_SHA256:
        raise ValueError("Unsupported package: this fork supports only the audited YTPlus 6.0 release")
    if not shutil.which("ldid"):
        raise ValueError("ldid is required to sign the modified library")
    with tempfile.TemporaryDirectory(prefix="ytplus-free-") as directory:
        root = Path(directory) / "package"
        unpack(package, root)
        library = root / LIBRARY_PATH
        library.write_bytes(patch_binary(library.read_bytes()))
        if localizations is not None:
            for language in sorted(localizations.glob("*.lproj")):
                if language.is_dir() and language.name != "en.lproj":
                    shutil.copytree(language, root / BUNDLE_PATH / language.name,
                                    dirs_exist_ok=True)
        translations = clean_localizations(root / BUNDLE_PATH)
        subprocess.run(["ldid", "-S", str(library)], check=True)
        control = root / "DEBIAN/control"
        control.write_text(re.sub(r"(?m)^Version:.*$", "Version: 6.0-free1", control.read_text()))
        checksums = []
        for path in sorted(root.rglob("*")):
            if path.is_file() and "DEBIAN" not in path.relative_to(root).parts:
                checksums.append(f"{hashlib.md5(path.read_bytes()).hexdigest()}  {path.relative_to(root)}\n")
        (root / "DEBIAN/md5sums").write_text("".join(checksums))
        output = Path(directory) / "free.deb"
        subprocess.run(["dpkg-deb", "--root-owner-group", "-b", str(root), str(output)], check=True)
        final_digest = digest(output.read_bytes())
        shutil.copyfile(output, package)
    report_path.write_text(json.dumps({
        "version": "6.0-free1", "upstream_package_sha256": PACKAGE_SHA256,
        "upstream_library_sha256": LIBRARY_SHA256, "package_sha256": final_digest,
        "changes": [name for name, *_ in PATCHES],
        "localizations_cleaned": translations, "ad_hoc_signed": True,
        "validation_scope": "ARM64 emulation and package checks; iOS device testing required",
    }, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("package", type=Path)
    parser.add_argument("--report", type=Path, default=Path("free-build-report.json"))
    parser.add_argument("--localizations", type=Path,
                        help="Optional repository translations to include before cleaning account strings")
    args = parser.parse_args()
    try:
        make_package(args.package, args.report, args.localizations)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.exit(1, f"Free build failed: {exc}\n")


if __name__ == "__main__":
    main()
