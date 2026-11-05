import hashlib
import io
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_artifacts
import package_app
import prepare_ipa
import supply_chain


class DownloadTests(unittest.TestCase):
    def test_wrong_digest_does_not_replace_existing_file(self):
        response = io.BytesIO(b"unexpected release replacement")
        response.url = "https://example.com/file"
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "package.deb"
            destination.write_bytes(b"previous download")
            with mock.patch.object(supply_chain.urllib.request, "build_opener") as opener:
                opener.return_value.open.return_value = response
                with self.assertRaisesRegex(ValueError, "SHA-256"):
                    supply_chain.download(response.url, destination, "0" * 64)
            self.assertEqual(destination.read_bytes(), b"previous download")
            self.assertEqual(list(Path(temp).iterdir()), [destination])

    def test_stream_size_limit_prevents_replacement(self):
        response = io.BytesIO(b"oversized")
        response.url = "https://example.com/file"
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(supply_chain.urllib.request, "build_opener") as opener:
            opener.return_value.open.return_value = response
            path = Path(temp) / "output"
            with self.assertRaisesRegex(ValueError, "size limit"):
                supply_chain.download(response.url, path, max_bytes=2)
            self.assertFalse(path.exists())
            self.assertFalse(list(Path(temp).iterdir()))

    def test_local_and_credential_urls_are_rejected(self):
        for url in ("file:///etc/passwd", "http://example.com/", "https://user:pass@example.com/a", "https://example.com/a\ncommand"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                supply_chain.require_https(url)

    def test_redirect_cannot_downgrade_https(self):
        handler = supply_chain.HTTPSRedirects()
        request = supply_chain.urllib.request.Request("https://example.com")
        with self.assertRaises(ValueError):
            handler.redirect_request(request, None, 302, "Found", {}, "http://example.com/file")


class SourceArchiveTests(unittest.TestCase):
    def archive(self, root, entries):
        path = root / "source.tar"
        with tarfile.open(path, "w") as tar:
            for name, kind in entries:
                item = tarfile.TarInfo(name)
                item.type = kind
                if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                    item.linkname = "../../outside"
                if kind == tarfile.REGTYPE:
                    item.size = 4
                tar.addfile(item, io.BytesIO(b"data") if kind == tarfile.REGTYPE else None)
        return path

    def test_valid_snapshot_is_extracted_without_its_archive_root(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive(root, [("repo/file.txt", tarfile.REGTYPE)])
            supply_chain.extract_source(archive, root / "snapshot")
            self.assertEqual((root / "snapshot/file.txt").read_bytes(), b"data")

    def test_unsafe_or_ambiguous_source_entries_leave_no_destination(self):
        cases = [
            [("repo/../../outside", tarfile.REGTYPE)],
            [("/absolute/file", tarfile.REGTYPE)],
            [("repo/symlink", tarfile.SYMTYPE)],
            [("repo/hardlink", tarfile.LNKTYPE)],
            [("repo/device", tarfile.CHRTYPE)],
            [("repo/A", tarfile.REGTYPE), ("repo/a", tarfile.REGTYPE)],
            [("one/file", tarfile.REGTYPE), ("two/file", tarfile.REGTYPE)],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive = self.archive(root, entries)
                with self.assertRaises(ValueError):
                    supply_chain.extract_source(archive, root / "snapshot")
                self.assertFalse((root / "snapshot").exists())


def macho(cryptid=0):
    return (struct.pack("<8I", 0xFEEDFACF, 0x100000C, 0, 2, 1, 24, 0, 0)
            + struct.pack("<6I", 0x2C, 24, 0, 0, cryptid, 0))


class IPAPreflightTests(unittest.TestCase):
    def make_ipa(self, root, extra=(), executable=None, identifier="com.google.ios.youtube"):
        path = root / "base.ipa"
        info = {"CFBundleIdentifier": identifier, "CFBundleExecutable": "YouTube",
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["youtube", "vnd.youtube"]}],
                "UIDesignRequiresCompatibility": True}
        with warnings.catch_warnings(), zipfile.ZipFile(path, "w") as archive:
            warnings.simplefilter("ignore", UserWarning)
            archive.writestr("Payload/YouTube.app/Info.plist", plistlib.dumps(info))
            archive.writestr("Payload/YouTube.app/YouTube", macho() if executable is None else executable)
            archive.writestr("iTunesMetadata.plist", b"store account metadata")
            for name, data in extra:
                archive.writestr(name, data)
        return path

    def test_valid_ipa_preserves_link_schemes_and_original_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = self.make_ipa(root)
            before = source.read_bytes()
            target = root / "prepared.ipa"
            prepare_ipa.prepare(source, target)
            self.assertEqual(source.read_bytes(), before)
            with zipfile.ZipFile(target) as archive:
                info = plistlib.loads(archive.read("Payload/YouTube.app/Info.plist"))
                self.assertEqual(info["CFBundleURLTypes"][0]["CFBundleURLSchemes"], ["youtube", "vnd.youtube"])
                self.assertNotIn("UIDesignRequiresCompatibility", info)
                self.assertIn("NSFaceIDUsageDescription", info)
                self.assertNotIn("iTunesMetadata.plist", archive.namelist())

    def test_traversal_duplicates_and_file_directory_conflicts_are_rejected(self):
        cases = [
            [("../../outside", b"bad")],
            [("/absolute/file", b"bad")],
            [("Payload\\YouTube.app\\file", b"bad")],
            [("Payload/YouTube.app/A", b"a"), ("Payload/YouTube.app/a", b"b")],
            [("Payload/YouTube.app/x", b"a"), ("Payload/YouTube.app/x/child", b"b")],
            [("Payload/YouTube.app/YouTube", b"duplicate")],
        ]
        for entries in cases:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                path = self.make_ipa(root, entries)
                with self.assertRaises(ValueError):
                    prepare_ipa.prepare(path, root / "output.ipa")
                self.assertFalse((root / "output.ipa").exists())

    def test_symbolic_links_and_privileged_files_are_rejected(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFREG | 0o4755, stat.S_IFCHR | 0o600):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                entry = zipfile.ZipInfo("Payload/YouTube.app/link")
                entry.create_system = 3
                entry.external_attr = mode << 16
                path = self.make_ipa(root, [(entry, b"../../outside")])
                with self.assertRaises(ValueError):
                    prepare_ipa.prepare(path, root / "output.ipa")

    def test_encrypted_secondary_image_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self.make_ipa(root, [("Payload/YouTube.app/Frameworks/a.dylib", macho(1))])
            with self.assertRaisesRegex(ValueError, "encrypted Mach-O"):
                prepare_ipa.prepare(path, root / "out.ipa")

    def test_additional_payload_tree_cannot_replace_the_validated_app(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self.make_ipa(root, [("Payload/Another.app/YouTube", macho())])
            with self.assertRaisesRegex(ValueError, "only the validated main app"):
                prepare_ipa.prepare(path, root / "out.ipa")

    def test_nested_or_overlapping_fat_images_are_rejected(self):
        thin = macho()
        fat = struct.pack(">II5I", 0xCAFEBABE, 1, 0x100000C, 0, 28, len(thin), 0) + thin
        self.assertEqual(prepare_ipa.cryptids(fat), [0])
        nested = struct.pack(">II5I", 0xCAFEBABE, 1, 0x100000C, 0, 28, len(fat), 0) + fat
        with self.assertRaisesRegex(ValueError, "Nested"):
            prepare_ipa.cryptids(nested)
        overlap = (struct.pack(">II", 0xCAFEBABE, 2)
                   + struct.pack(">5I", 0x100000C, 0, 48, len(thin), 0) * 2 + thin)
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            prepare_ipa.cryptids(overlap)

    def test_preinjected_or_unrelated_apps_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self.make_ipa(root, [("Payload/YouTube.app/Frameworks/YTLite.dylib", macho())])
            with self.assertRaisesRegex(ValueError, "already contains"):
                prepare_ipa.prepare(path, root / "out.ipa")
            path = self.make_ipa(root, identifier="example.unrelated.app")
            with self.assertRaisesRegex(ValueError, "original YouTube"):
                prepare_ipa.prepare(path, root / "out.ipa")

    def test_truncated_load_commands_are_rejected(self):
        for data in (macho()[:35], macho()[:32], macho()[:20]):
            with self.subTest(data=data), self.assertRaises(ValueError):
                prepare_ipa.cryptids(data)

    def test_excessive_advertised_expansion_is_rejected_before_reading(self):
        item = zipfile.ZipInfo("Payload/YouTube.app/huge")
        item.file_size = prepare_ipa.MAX_MEMBER + 1
        archive = mock.Mock()
        archive.infolist.return_value = [item]
        with self.assertRaisesRegex(ValueError, "size limit"):
            prepare_ipa.check_members(archive)
        archive.open.assert_not_called()


class ArtifactIntegrityTests(unittest.TestCase):
    def package(self, root, script=False):
        tree = root / "package"
        (tree / "DEBIAN").mkdir(parents=True)
        (tree / "DEBIAN/control").write_text("Package: com.example.test\nVersion: 1.0\nArchitecture: all\nMaintainer: Test\nDescription: Test fixture\n")
        if script:
            (tree / "DEBIAN/postinst").write_text("#!/bin/sh\necho should-never-execute\n")
            (tree / "DEBIAN/postinst").chmod(0o755)
        output = root / "ytplus.deb"
        subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(tree), str(output)], check=True, stdout=subprocess.DEVNULL)
        (root / build_artifacts.REPORT).write_text(json.dumps({"package_sha256": build_artifacts.digest(output)}))
        return output

    def test_modified_optional_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            core = self.package(root)
            optional = root / "youpip.deb"
            optional.write_bytes(core.read_bytes())
            manifest = root / "built-inputs.json"
            build_artifacts.write_manifest(root, manifest)
            self.assertEqual(len(build_artifacts.verify_manifest(root, manifest)), 2)
            optional.write_bytes(b"replaced package")
            with self.assertRaisesRegex(ValueError, "have changed"):
                build_artifacts.verify_manifest(root, manifest)

    def test_unreviewed_maintainer_script_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = self.package(root, script=True)
            with self.assertRaisesRegex(ValueError, "maintainer script"):
                build_artifacts.validate_deb(path)

    def test_unexpected_deb_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.package(root)
            (root / "unreviewed.deb").write_bytes(b"unreviewed")
            with self.assertRaisesRegex(ValueError, "Unexpected DEB"):
                build_artifacts.artifact_files(root)


class WorkflowBoundaryTests(unittest.TestCase):
    def test_app_name_is_data_even_when_it_contains_shell_syntax(self):
        value = 'YouTube $(touch /tmp/never-run) `id` "quoted"'
        with mock.patch.dict(os.environ, {"DISPLAY_NAME": value, "BUNDLE_ID": "com.example.youtube"}), mock.patch.object(sys, "argv", ["package_app", "ipa"]), mock.patch.object(package_app, "verify_manifest", return_value=[Path("ytplus.deb")]), mock.patch.object(package_app.subprocess, "run") as run:
            package_app.main()
            command = run.call_args.args[0]
            self.assertIn(f"-n={value}", command)
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_option_shaped_app_name_stays_a_single_argument_value(self):
        with mock.patch.dict(os.environ, {"DISPLAY_NAME": "--fakesign", "BUNDLE_ID": "com.example.youtube"}), mock.patch.object(sys, "argv", ["package_app", "ipa"]), mock.patch.object(package_app, "verify_manifest", return_value=[Path("ytplus.deb")]), mock.patch.object(package_app.subprocess, "run") as run:
            package_app.main()
            self.assertIn("-n=--fakesign", run.call_args.args[0])
            self.assertNotIn("--fakesign", run.call_args.args[0])

    def test_bundle_identifier_cannot_inject_extra_arguments(self):
        for value in ('com.example.app; touch marker', 'com.example.app --other', '-b', 'com.example.app\ncommand'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                prepare_ipa.validate_identity("YouTube", value)

    def test_workflows_use_immutable_action_versions(self):
        folder = Path(__file__).resolve().parents[1] / ".github/workflows"
        for path in folder.glob("*.yml"):
            text = path.read_text()
            for target in re.findall(r"uses:\s*([^\s]+)", text):
                if not target.startswith("./"):
                    self.assertRegex(target, r"^[A-Za-z0-9_./-]+@[0-9a-f]{40}$", path.name)

    def test_text_inputs_do_not_become_shell_script_source(self):
        folder = Path(__file__).resolve().parents[1] / ".github/workflows"
        for path in folder.glob("*.yml"):
            lines = path.read_text().splitlines()
            for i, line in enumerate(lines):
                match = re.match(r"^(\s*)run:\s*(.*)", line)
                if not match:
                    continue
                indent = len(match[1])
                script = [match[2]]
                for following in lines[i+1:]:
                    if following.strip() and len(following)-len(following.lstrip()) <= indent:
                        break
                    script.append(following)
                self.assertNotRegex("\n".join(script), r"\$\{\{[^}]*inputs\.", path.name)


if __name__ == "__main__":
    unittest.main()
