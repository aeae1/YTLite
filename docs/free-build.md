# Offline YouTube Plus 6.0 build

Dependency and workflow hardening is described in [the security review](security-review.md).

This fork keeps the 6.0 implementation and modifies the published arm64 library
at build time. It does not replace it with the older 3.0.1 source files or the
5.2b4 release.

The changes are deliberately restricted to four entry points:

| Entry point | Offline behavior |
| --- | --- |
| Feature initializer registration | Execute each initialization block immediately, with its original block context. |
| Preference activation check | Allow boolean and integer settings to be read without account activation. Preserve the user's actual setting values. |
| Account service constructor | Return immediately without starting authentication or account refresh work. |
| Account settings section | Return an empty section with no login, status, device-limit, or subscription controls. |

Account-related localization entries are removed from all bundled languages.
Google account login, the normal YouTube channel Subscriptions tab, and
voluntary developer credits are separate and remain available.

## Reproducibility

Only the exact original `6.0` rootful arm64 package is accepted. Both the DEB
and its library must match their recorded SHA-256 digests. A replacement asset,
another architecture, or a newer upstream version causes a clear failure.
Workflows cannot silently package a different paid version.

`scripts/free_ytplus.py` changes the library, incorporates optional translations,
cleans the account strings, signs the modified library with `ldid`, updates
Debian package checksums and its version to `6.0-free1`, and writes a build report.
Production patching requires only Python's standard library, dpkg, and ldid.
The original downloaded library is never executed on the build host.

## Verification and limits

The ARM64 tests execute the affected routines in Unicorn with Foundation and
keychain/network boundaries mocked. They check that an enabled preference is
blocked by the original library but works after modification, that disabled
and unset preferences stay disabled, that integers retain their values, and
that initialization blocks run with the correct context. They also check
the account constructor, replacement section, identity guards, preservation
of unrelated binary regions, and localization cleanup.

The `Validate free YTPlus package` workflow repeats these checks and builds a
signed DEB. Its artifact includes `ytplus.deb` and `free-build-report.json`.
It does not need a YouTube IPA.

These checks do **not** establish that every 6.0 feature works on an iPhone.
A device smoke test is still needed: cold start without a YTPlus account,
open settings, change settings and restart, play video in the standard and
YTPlus players, download a video, exercise background playback and PiP, and
relaunch offline. The app and iOS versions should be recorded with those results.

There is no matching current upstream source in this repository. Future releases
need a separate audit, new digest checks, and fresh device testing before they
can be supported.
