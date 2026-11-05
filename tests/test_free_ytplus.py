import os
from pathlib import Path
import plistlib
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from free_ytplus import PATCHES, clean_localizations, patch_binary
from macho_harness import Harness


class OfflineAccessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("YTPLUS_TEST_LIBRARY")
        if not path or not Path(path).is_file():
            raise RuntimeError("Set YTPLUS_TEST_LIBRARY to the original, audited YTPlus 6.0 arm64 dylib")
        cls.original_path = Path(path)
        cls.original = cls.original_path.read_bytes()
        cls.patched = patch_binary(cls.original)
        cls.directory = tempfile.TemporaryDirectory()
        cls.patched_path = Path(cls.directory.name) / "YTLite.dylib"
        cls.patched_path.write_bytes(cls.patched)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def harness(self, original=False):
        return Harness(self.original_path if original else self.patched_path)

    def test_original_requires_activation_but_patched_preserves_boolean_choices(self):
        original = self.harness(original=True)
        key = original.obj("examplePreference")
        original.prefs["examplePreference"] = 1
        self.assertEqual(original.call(0xC1DDC, (key,)), 0)
        for value in (0, 1):
            patched = self.harness()
            key = patched.obj("examplePreference")
            patched.prefs["examplePreference"] = value
            self.assertEqual(patched.call(0xC1DDC, (key,)), value)
            self.assertFalse(any(event[0] == "external" for event in patched.events))

    def test_integer_preferences_work_without_an_account(self):
        patched = self.harness()
        key = patched.obj("examplePreference")
        patched.prefs["examplePreference"] = 425
        self.assertEqual(patched.call(0xC2AA4, (key,)), 425)
        self.assertFalse(any(event[0] == "external" for event in patched.events))

    def test_missing_preferences_keep_their_default(self):
        patched = self.harness()
        key = patched.obj("unsetPreference")
        self.assertEqual(patched.call(0xC1DDC, (key,)), 0)
        self.assertEqual(patched.call(0xC2AA4, (key,)), 0)

    def test_activation_check_does_not_access_keychain_or_network(self):
        patched = self.harness()
        self.assertEqual(patched.call(0xC24BC), 1)
        self.assertEqual(patched.events, [])

    def test_feature_initializers_run_immediately_with_their_block_context(self):
        patched = self.harness()
        block = patched.obj("initializer block")
        invoke = patched.obj("initializer code")
        patched.uc.mem_write(invoke, struct.pack("<II", 0xF9401000, 0xD65F03C0))
        patched.putptr(block + 16, invoke)
        patched.putptr(block + 32, 0x1234)
        self.assertEqual(patched.call(0xBF314, (block,)), 0x1234)
        self.assertEqual(patched.events, [])

    def test_account_service_is_not_started(self):
        patched = self.harness()
        patched.call(0xC804C)
        self.assertEqual(patched.events, [])

    def test_account_ui_is_replaced_with_an_empty_section(self):
        patched = self.harness()
        result = patched.call(0x34B160, (0, 0, 0))
        self.assertEqual(patched.describe(result),
                         {"class": "DVNSection", "cells": [], "identifier": None})
        self.assertEqual(len(patched.events), 1)
        self.assertEqual(patched.events[0][2], "sectionWithIdentifier:")

    def test_unknown_modified_and_already_patched_libraries_are_rejected(self):
        modified = bytearray(self.original)
        modified[-1] ^= 1
        for data in (bytes(modified), self.patched, b"unsupported library"):
            with self.assertRaisesRegex(ValueError, "Unsupported library"):
                patch_binary(data)

    def test_unrelated_code_and_resources_are_unchanged(self):
        cursor = 0
        for _, offset, _, replacement in sorted(PATCHES, key=lambda patch: patch[1]):
            self.assertEqual(self.original[cursor:offset], self.patched[cursor:offset])
            cursor = offset + len(replacement)
        self.assertEqual(self.original[cursor:], self.patched[cursor:])


class LocalizationTests(unittest.TestCase):
    def test_binary_and_text_translations_keep_google_login_and_channel_subscriptions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = {"Access.Status": "Subscription status", "LogIn": "Log in",
                      "FeaturesNotActivated": "An active subscription is required",
                      "LoginInfo": "Sign into your Google account",
                      "FEsubscriptions": "Subscriptions", "Player": "Player"}
            binary = root / "en.lproj/Localizable.strings"
            binary.parent.mkdir()
            binary.write_bytes(plistlib.dumps(values, fmt=plistlib.FMT_BINARY))
            text = root / "es.lproj/Localizable.strings"
            text.parent.mkdir()
            text.write_text('"Access.Status" = "Status";\n"LoginInfo" = "Google account";\n')
            self.assertEqual(clean_localizations(root), 2)
            self.assertEqual(plistlib.loads(binary.read_bytes()),
                             {k: v for k, v in values.items()
                              if k in {"LoginInfo", "FEsubscriptions", "Player"}})
            self.assertEqual(text.read_text(), '"LoginInfo" = "Google account";\n')


if __name__ == "__main__":
    unittest.main()
