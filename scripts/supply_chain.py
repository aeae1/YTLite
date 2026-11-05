#!/usr/bin/env python3
"""Fetch the reviewed dependency bytes recorded in dependencies.lock.json."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

LOCK = Path(__file__).resolve().parents[1] / "dependencies.lock.json"


def require_https(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or any(ord(c) <= 32 for c in url)):
        raise ValueError("A valid HTTPS URL without credentials is required")


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        require_https(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url, destination, expected=None, max_bytes=2_000_000_000):
    """Stream to a temporary file; never expose a partial or mismatched result."""
    require_https(url)
    if expected is not None and not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Invalid SHA-256 digest")
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(HTTPSRedirects())
    request = urllib.request.Request(url, headers={"User-Agent": "YTPlus-reviewed-builder/1"})
    h = hashlib.sha256()
    total = 0
    name = None
    try:
        with opener.open(request, timeout=60) as response, tempfile.NamedTemporaryFile(
                dir=destination.parent, delete=False) as output:
            name = output.name
            require_https(response.url)
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > max_bytes:
                    raise ValueError("Download exceeds the size limit")
                output.write(block)
                h.update(block)
        if expected is not None and h.hexdigest() != expected:
            raise ValueError("Downloaded bytes do not match the reviewed SHA-256 digest")
        os.replace(name, destination)
        return h.hexdigest()
    except urllib.error.HTTPError as error:
        raise ValueError(f"Download failed (HTTP {error.code})") from None
    except urllib.error.URLError:
        # Signed input URLs may contain secrets; do not put them in logs.
        raise ValueError("HTTPS download failed") from None
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


def extract_source(archive, destination):
    destination = Path(destination)
    if destination.exists():
        raise ValueError("Source destination already exists; use a fresh directory")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=destination.parent) as temp, tarfile.open(archive) as tar:
        members = tar.getmembers()
        if not members or len(members) > 30_000:
            raise ValueError("Invalid source archive member count")
        top = None
        total = 0
        seen = set()
        for member in members:
            name = member.name
            path = PurePosixPath(name)
            if (path.is_absolute() or ".." in path.parts or "\\" in name
                    or "\0" in name or not path.parts or not (member.isdir() or member.isfile())):
                raise ValueError("Unsafe source archive entry")
            top = top or path.parts[0]
            if path.parts[0] != top:
                raise ValueError("Source archive must have one root directory")
            total += member.size
            if total > 512_000_000 or member.size > 128_000_000:
                raise ValueError("Expanded source archive exceeds the size limit")
            if len(path.parts) == 1:
                if not member.isdir():
                    raise ValueError("Source root must be a directory")
                continue
            relative = PurePosixPath(*path.parts[1:])
            if str(relative).casefold() in seen:
                raise ValueError("Duplicate source archive path")
            seen.add(str(relative).casefold())
            item = copy.copy(member)
            item.name = str(relative)
            tar.extract(item, temp, filter="data")
        shutil.move(temp, destination)


def fetch_source(name, destination, lock=None):
    lock = lock or json.loads(LOCK.read_text())
    source = lock["sources"][name]
    repo, commit = source["repository"], source["commit"]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Dependency must name a repository and a complete commit SHA")
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "source.tar.gz"
        download(f"https://codeload.github.com/{repo}/tar.gz/{commit}", archive,
                 source["sha256"], max_bytes=64_000_000)
        extract_source(archive, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=("source", "asset"))
    parser.add_argument("name")
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    try:
        lock = json.loads(LOCK.read_text())
        if lock["schema"] != 1:
            raise ValueError("Unsupported dependency lock schema")
        if args.kind == "source":
            fetch_source(args.name, args.destination, lock)
        else:
            asset = lock["assets"][args.name]
            download(asset["url"], args.destination, asset["sha256"], asset["max_bytes"])
    except (ValueError, KeyError, OSError, tarfile.TarError) as error:
        parser.exit(1, f"Dependency validation failed: {error}\n")


if __name__ == "__main__":
    main()
