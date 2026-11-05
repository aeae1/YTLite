#!/usr/bin/env python3
"""Preflight an IPA before the external packager extracts or modifies it."""
import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import struct
import tempfile
import unicodedata
import zipfile

from supply_chain import download

MAX_FILES = 100_000
MAX_EXPANDED = 4_000_000_000
MAX_MEMBER = 1_000_000_000


def validate_identity(name, bundle_id):
    if not name or len(name) > 80 or any(ord(c) < 32 or ord(c) == 127 for c in name):
        raise ValueError("App name must be 1–80 characters without control characters")
    if len(bundle_id) > 255 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+", bundle_id):
        raise ValueError("Invalid app bundle identifier")


def check_members(archive):
    members = archive.infolist()
    if not members or len(members) > MAX_FILES:
        raise ValueError("Invalid ZIP member count")
    total, seen = 0, set()
    for item in members:
        name = item.orig_filename
        path = PurePosixPath(name)
        if (not path.parts or path.is_absolute() or ".." in path.parts or "\\" in name
                or "\0" in name or ":" in path.parts[0]):
            raise ValueError("Unsafe ZIP path")
        key = unicodedata.normalize("NFC", str(path)).casefold()
        if key in seen:
            raise ValueError("Duplicate ZIP path")
        seen.add(key)
        mode = item.external_attr >> 16
        if (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)
                or mode & 0o6000 or item.flag_bits & 1):
            raise ValueError("Links, special files, privileged modes, and encrypted ZIP entries are not accepted")
        total += item.file_size
        if item.file_size > MAX_MEMBER or total > MAX_EXPANDED:
            raise ValueError("Expanded IPA exceeds the size limit")
    # Reject a regular file used as an ancestor before an extractor can touch it.
    regular = {unicodedata.normalize("NFC", str(PurePosixPath(i.filename))).casefold()
               for i in members if not i.is_dir()}
    for item in members:
        path = PurePosixPath(item.filename)
        if any(unicodedata.normalize("NFC", str(p)).casefold() in regular for p in path.parents if str(p) != "."):
            raise ValueError("ZIP file and directory paths conflict")
    return members


def cryptids(data, allow_fat=True):
    """Inspect thin/fat Mach-O load commands without loading native code."""
    if len(data) < 4:
        raise ValueError("Truncated Mach-O image")
    magic = data[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        if not allow_fat:
            raise ValueError("Nested fat Mach-O images are not accepted")
        if len(data) < 8:
            raise ValueError("Truncated fat Mach-O header")
        count = struct.unpack_from(">I", data, 4)[0]
        stride = 32 if magic.endswith(b"\xbf") else 20
        if not 1 <= count <= 16 or 8 + count * stride > len(data):
            raise ValueError("Invalid fat Mach-O header")
        results, ranges = [], []
        for i in range(count):
            start = 8 + i * stride
            offset, size = struct.unpack_from(">QQ" if stride == 32 else ">II", data, start + 8)
            if size < 28 or offset < 8 + count * stride or offset + size > len(data):
                raise ValueError("Invalid fat Mach-O slice")
            if any(offset < previous_end and previous_start < offset + size
                   for previous_start, previous_end in ranges):
                raise ValueError("Overlapping fat Mach-O slices are not accepted")
            ranges.append((offset, offset + size))
            results.extend(cryptids(data[offset:offset + size], allow_fat=False))
        return results
    if magic not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        raise ValueError("Expected an iOS Mach-O executable")
    header_size = 32 if magic == b"\xcf\xfa\xed\xfe" else 28
    if len(data) < header_size:
        raise ValueError("Truncated Mach-O header")
    if struct.unpack_from("<I", data, 4)[0] not in (12, 0x100000C):
        raise ValueError("Executable is not an iOS ARM image")
    count, command_bytes = struct.unpack_from("<II", data, 16)
    if count > 20_000 or command_bytes > len(data) - header_size:
        raise ValueError("Invalid Mach-O load commands")
    end, offset, result = header_size + command_bytes, header_size, []
    for _ in range(count):
        if offset + 8 > end:
            raise ValueError("Truncated load command")
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or size % 4 or offset + size > end:
            raise ValueError("Invalid load command size")
        if command in (0x21, 0x2C):
            if size < (24 if command == 0x2C else 20):
                raise ValueError("Truncated encryption command")
            result.append(struct.unpack_from("<I", data, offset + 16)[0])
        offset += size
    if offset != end:
        raise ValueError("Mach-O load command count does not match size")
    return result


def prepare(source, destination):
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Use a different output path to preserve the input IPA")
    with zipfile.ZipFile(source) as archive:
        members = check_members(archive)
        main_plists = [i.filename for i in members if re.fullmatch(r"Payload/[^/]+\.app/Info\.plist", i.filename)]
        if len(main_plists) != 1:
            raise ValueError("IPA must contain exactly one main app")
        plist_name = main_plists[0]
        plist_info = archive.getinfo(plist_name)
        if plist_info.file_size > 4_000_000:
            raise ValueError("Main app plist exceeds the size limit")
        plist = plistlib.loads(archive.read(plist_name))
        if plist.get("CFBundleIdentifier") != "com.google.ios.youtube":
            raise ValueError("Use an original YouTube IPA as the input")
        executable = plist.get("CFBundleExecutable")
        if not isinstance(executable, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", executable):
            raise ValueError("Invalid main executable name")
        app = plist_name.rsplit("/", 1)[0]
        main = f"{app}/{executable}"
        if any(i.filename.startswith("Payload/") and i.filename.rstrip("/") not in ("Payload", app)
               and not i.filename.startswith(app + "/") for i in members):
            raise ValueError("Payload must contain only the validated main app")
        known_tweaks = {"ytlite.dylib", "ytplus.dylib", "uyou.dylib", "cydiasubstrate"}
        for item in members:
            if PurePosixPath(item.filename).name.casefold() in known_tweaks:
                raise ValueError("Input IPA already contains an injected tweak or loader")
            if item.is_dir():
                continue
            with archive.open(item) as f:
                head = f.read(4)
                if head in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
                    if item.file_size > 512_000_000:
                        raise ValueError("Executable exceeds the analysis size limit")
                    if any(cryptids(head + f.read())):
                        raise ValueError("IPA contains an encrypted Mach-O image; use a decrypted input")
                elif item.filename == main:
                    raise ValueError("Main executable is not Mach-O")
        archive.getinfo(main)
        plist.pop("UIDesignRequiresCompatibility", None)
        plist.setdefault("NSFaceIDUsageDescription", "Face ID is used to protect your YouTube settings.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=destination.parent) as temp:
            output = Path(temp) / "prepared.ipa"
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as target:
                for item in members:
                    # The packager uses Payload only; omit account/store metadata outside it.
                    if not item.filename.startswith("Payload/"):
                        continue
                    if item.filename == plist_name:
                        target.writestr(item, plistlib.dumps(plist, fmt=plistlib.FMT_BINARY, sort_keys=False))
                    else:
                        with archive.open(item) as src, target.open(item, "w") as dst:
                            shutil.copyfileobj(src, dst, 1024 * 1024)
            os.replace(output, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--download", action="store_true", help="Download IPA_URL to the input path first")
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        validate_identity(os.environ.get("DISPLAY_NAME", "YouTube"),
                          os.environ.get("BUNDLE_ID", "com.google.ios.youtube"))
        if args.download:
            url = os.environ.get("IPA_URL", "")
            escaped = url.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::add-mask::{escaped}", flush=True)
            download(url, args.source)
        prepare(args.source, args.destination)
        with args.source.open("rb") as source:
            h = hashlib.file_digest(source, "sha256").hexdigest()
        print(f"Input IPA SHA-256: {h}")
    except (ValueError, OSError, KeyError, zipfile.BadZipFile, plistlib.InvalidFileException) as error:
        parser.exit(1, f"IPA validation failed: {error}\n")


if __name__ == "__main__":
    main()
