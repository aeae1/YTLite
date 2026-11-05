#!/usr/bin/env python3
"""Package verified build outputs using the reviewed cyan snapshot, without a shell."""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

from build_artifacts import verify_manifest
from free_ytplus import unpack
from prepare_ipa import validate_identity


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("format", choices=("ipa", "cyan", "trollfools"))
    args = parser.parse_args()
    try:
        root = Path.cwd()
        inputs = verify_manifest(root, root / "built-inputs.json")
        name = os.environ.get("DISPLAY_NAME", "YouTube")
        bundle = os.environ.get("BUNDLE_ID", "com.google.ios.youtube")
        validate_identity(name, bundle)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(root / "vendor/cyan")
        if args.format == "trollfools":
            with tempfile.TemporaryDirectory() as temp:
                temp = Path(temp)
                with zipfile.ZipFile("TrollFools_YouTubePlus_6.0-free1.zip", "w", zipfile.ZIP_DEFLATED) as archive:
                    seen = set()
                    for i, package in enumerate(p for p in inputs if p.suffix == ".deb"):
                        tree = temp / str(i)
                        unpack(package, tree)
                        for path in sorted(tree.rglob("*")):
                            if path.is_file() and (path.suffix == ".dylib" or any(p.endswith(".bundle") for p in path.parts)):
                                parts = path.relative_to(tree).parts
                                start = next((j for j, p in enumerate(parts) if p.endswith(".bundle")), len(parts)-1)
                                relative = str(Path(*parts[start:]))
                                if relative in seen:
                                    raise ValueError("TrollFools resources have conflicting names")
                                seen.add(relative)
                                archive.write(path, relative)
            return
        command = [sys.executable, "-m", "cyan" if args.format == "ipa" else "cgen"]
        if args.format == "ipa":
            command += ["-i", "youtube.ipa", "--overwrite"]
        command += ["-o", "YouTubePlus_6.0-free1.ipa" if args.format == "ipa" else "cyan_YouTubePlus_6.0-free1.cyan",
                    "-u", "-w", "-e", "-f", *map(str, inputs), f"-n={name}", f"-b={bundle}"]
        subprocess.run(command, check=True, env=env)
    except (ValueError, OSError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Packaging failed: {error}\n")


if __name__ == "__main__":
    main()
