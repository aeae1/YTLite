# Security review: 2026-11-05

## Decision

Keep the official final YTPlus 6.0 core and the existing four-entry-point offline patch. The activation behavior confirmed in MaxTube's beta is already covered by this patch. No MaxTube binary, Queue, Extras, or additional MaxTube-only tweak has been imported into this fork.

The review found no obvious malicious payload in the inspected components. This is a scoped static review and isolated emulation result, not a guarantee that MaxTube or YTPlus is malware-free. The current YTPlus implementation is obfuscated and supplied as a compiled library, and the original unmodified 6.0 beta 2 binary was unavailable for a complete same-version comparison. An actual ready-made Telegram IPA was not inspected. Do not apply these findings to an arbitrary IPA, mirror, or later release.

The useful changes here are to dependency integrity, input handling, artifact verification, and build permissions. They do not change initialization timing or add the beta's redundant activation-return patches. Startup reliability and actual network behavior still need iPhone testing.

## Build issues fixed in this fork

| Issue found | Change |
| --- | --- |
| Add-ons, headers, SDKs, the packager, and Safari extension were fetched from moving branches; actions used mutable version tags | Pin source commits and action commits. Source archives additionally require an exact SHA-256 before extraction. The core retains both whole-package and library identity checks. |
| Display names, bundle IDs, and IPA URLs were expanded into shell source | Put text inputs in environment variables, validate app identity, and pass packager parameters as a subprocess argument list. The download URL is masked and is not recorded in the artifact manifest. |
| A ZIP/MIME check preceded unrestricted IPA extraction | Preflight the whole archive: reject path traversal, links, device files, privileged modes, conflicting or duplicate names, expansion limits, invalid Mach-O commands, encrypted images, and recognized existing tweak injection. Preserve the original input and YouTube URL schemes. |
| Packaging third-party code ran in a job with repository-write permissions | Build and packaging jobs have read-only contents access and do not retain checkout credentials. A separate draft-release job has write access and does not execute packaged app code. |
| Downloaded build artifacts were consumed without an inventory check | Verify package/resource SHA-256 values and the dependency-lock digest before packaging. Reject unknown DEBs, links, and DEB maintainer scripts. Check the signed core's patch locations, version, and localization cleanup. |
| The Safari extension was always added | Make it an explicit optional choice, off by default, consistent with the four minimal IPAs previously produced. |
| Earlier macOS jobs did not acquire a runner | Run isolated code/security tests on Ubuntu and use an explicit Intel macOS runner for signing and packaging. The earlier job annotations reported hosted-runner capacity constraints, not a test assertion failure. |

The lock is in [dependencies.lock.json](../dependencies.lock.json). Updating it is a new code-review decision; a hash match establishes byte identity, not that those bytes are benign. Theos submodules remain locked by its recorded gitlinks. The selected SDK is pinned to a commit. GitHub's runner image, Xcode, Homebrew tools, and the operating system remain part of the build platform trust boundary; this is not a fully hermetic build.

## What was inspected

The exact versions, source commits, archive hashes, and observed package hashes are recorded in [security-inventory.json](security-inventory.json). The review fetched 23 source snapshots covering the current fork's dependencies and the repositories referenced by MaxTube's normal build helper. It also inspected six Debian packages: MaxTube's 6.0 beta 2 core, its older 5.2.2 core, their available official counterparts, Queue 1.0.0, and Extras 1.2.0.

Methods included archive/control-file inspection without installing packages, source searches and review of build/network/clipboard/process paths, Mach-O load-command/import/selector and string inspection, a matching-version section comparison for 5.2.2, and the previously recorded isolated ARM64 activation probes. A missing suspicious string or import alone is not treated as proof of safety. Runtime hooks, dynamic symbol lookup, sockets, and keychain APIs can serve legitimate features and require context.

### YTPlus cores

- The reviewed packages had no maintainer scripts, launch-daemon payloads, or privileged-mode files. They contained the expected tweak library, filter plist, and resources.
- The MaxTube 5.2.2 library has the same-sized executable section as the official 5.2.2 library. Sixteen instruction words, covering 54 differing bytes, change in that section. The changes set activation-related return/flag values. All other compared file-backed data sections match. This provides a narrow, strong comparison for that older package; it does not establish the contents of the newer beta or a complete IPA.
- The MaxTube 6.0 beta 2 core has expected media, Objective-C hook, network, SQLite, and keychain imports. Its readable URL strings overlap those of official 6.0 and include media-library references. Some upstream HTML strings reference jsDelivr-hosted JavaScript modules. Their presence is not attributed to MaxTube, and complete reachability/data exposure of those features was not established.
- The beta retains account-section construction and account-related startup code. The current fork's patch disables the selected startup entry point and replaces the account section with an empty section. This does not establish that every possible licensing/network path in the compiled implementation is unreachable.
- The beta's original release API and asset links returned 404 during the earlier analysis. Other differences between beta and final cannot be labeled as modifications made by MaxTube.

### MaxTube Queue and Extras

The inspected Queue binary contains ARM64 and ARM64e slices with about 14 KB of code per slice. Extras contains about 2.3 KB of code. Their visible functions/selectors and dependencies fit queue management and settings grouping, respectively. No obvious credential-access, process-launch, additional network-library, or hard-coded HTTP destination was found in those small components. Their inspected DEBs have no install scripts.

Both are prebuilt files hosted on Catbox. MaxTube's helper does not pin their content hashes, and matching source/build provenance was not available. The hashes in the inventory identify only the bytes obtained during this review; they are not an independent publisher attestation. These components are not in the build lock and are not imported.

### Source-based add-ons

The reviewed player-control, quality, low-contrast, loop, mute, caption-copy, and UI tweaks contain behavior consistent with their descriptions. Source review found no obvious credential theft or unrelated data upload. This is not a guarantee of compatibility, correctness, or the contents of separately distributed binaries.

Network and data-handling behavior that matters when selecting extras:

| Component | Observed behavior |
| --- | --- |
| Return YouTube Dislikes | Calls `returnyoutubedislikeapi.com` with video IDs. Its optional voting flow uses a generated user identifier and like/dislike values. This is functional data sharing with a third-party service, not a local-only feature. It remains off by default. |
| Gonerino | Contains a GitHub release-update check and user-initiated support links; its UI also imports user-selected local filter data. It is not imported by this fork. |
| YTABConfig | Reads the clipboard in its user-invoked import-settings flow and writes it for export/copy actions. |
| YouGetCaption / YouShare | Writes caption text or video links to the clipboard in response to user actions. They are not imported by this fork. |
| PSHeader | Provides a process-restart helper and camera-related macros used across multiple projects. Presence in a header does not establish that all of those helpers are compiled or invoked by a selected tweak. |
| YTVideoOverlay / YouSpeed | References local tweak libraries for loading or compatibility checks. No remote executable-download path was found in those inspected call sites. |

Source snapshots can include build helpers or unused headers in addition to the code actually compiled. The review does not claim an exhaustive dependency-vulnerability audit or that every optional combination has compiled or run on an iPhone. The existing six optional build choices remain opt-in.

One robustness concern remains in the optional RYD voting implementation: its puzzle solver copies 16 challenge bytes without first validating the decoded length and derives work from an unchecked server-supplied difficulty. This is an input-validation concern, not evidence of malicious intent. That parser has not been changed or validated here; keep the add-on disabled when using the minimal reviewed configuration.

### Safari extension and packager

The optional Safari extension's readable manifest targets YouTube pages and declares no additional WebExtension permissions. Its JavaScript redirects matching YouTube URLs to the `youtube://` scheme; no JavaScript fetch/XHR or third-party destination was found. The native Swift extension binary is prebuilt rather than reproduced from matching source in this repository. It is locked as part of the archive and remains off by default. A separate app ID does not guarantee how iOS will choose between apps claiming the same scheme.

The pinned cyan Python package uses subprocess argument lists for local archive, Mach-O, and signing utilities. Its setup file declares no additional Python runtime dependencies. It bundles native host utilities and runtime frameworks, which were not rebuilt from source in this review. The required CydiaSubstrate-named loader is an ElleKit-based implementation; its inspected imports are consistent with in-process hooking and Swift/Foundation support, with no hard-coded HTTP destination found. That loader and the packager's native utilities remain binary trust boundaries. Pinning the entire source archive prevents silent replacement but cannot certify them.

## Validation and remaining work

The local suite exercises the existing activation/initialization behavior and hostile download/archive/artifact inputs, including shell-shaped app names, traversal, links, duplicate names, pre-injected apps, encrypted secondary images, altered artifacts, and unreviewed DEB maintainer scripts. The IPA preflight was also run on both supplied YouTube versions, 21.43.5 and 21.44.4, without modifying the original files.

CI repeats these checks and separately builds, signs, and verifies the core on macOS. A successful static check or ad-hoc signature verifies a limited property; it is not an Apple authenticity attestation or an iPhone execution test. Inspect the actual CI result for the commit being used.

The remaining device checks are cold startup, setting changes and persistence, ordinary/Plus player playback, downloads, background/PiP behavior, offline relaunch, link routing after personal signing, and account/network traffic. Do not change the initialization strategy merely because the beta's registration path differs: a timing change needs device evidence.
