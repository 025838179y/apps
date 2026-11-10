# UniversalAuth Face Unlock — PIN / Pattern customization

This repository contains a patch and GitHub Actions build pipeline for the original UniversalAuth Face Unlock app (application ID `ax.nd.faceunlock`), based on upstream release commit `0c45755260538792b30a97d8775e3936e8428564`.

## Added to the original app

- Optional numeric PIN (at least 6 digits).
- Optional 3×3 gesture pattern (at least 4 connected points).
- Both can be enabled together alongside the original face authentication.
- PIN and pattern are stored as salted PBKDF2-HMAC-SHA256 hashes, not plaintext.
- Five failed attempts temporarily block the custom credential UI for 30 seconds.
- A Magisk/SU button runs only `su -c id` to request and verify superuser authorization.
- A settings button opens Android Accessibility settings, where the app's existing lock-screen accessibility service can be enabled.

## Android lock-screen boundary

Android does not offer an ordinary app setting that makes a third-party app the system Keyguard. This project keeps the original UniversalAuth architecture: the accessibility service displays the additional credential UI over the lock screen, and the existing Xposed/LSPosed module handles the system-unlock path. The Magisk button is only a permission check; it does not by itself install or activate the Xposed module.

## Build

A push to `main`, or a manual run under **Actions → Build original Face Unlock with PIN and Pattern**, clones the pinned upstream source, applies `patches/patch_original.py`, and builds the original app's debug APK.

The output is uploaded as the workflow artifact `original-face-unlock-pin-pattern-debug`.

The APK is debug-signed. Updating an already-installed copy of the original app requires signing with the same private release keystore that signed that installed copy; that keystore is not included in this repository and should never be committed.

## Attribution

The upstream UniversalAuth source is distributed under the Apache License 2.0 terms described in its `LICENSE.md`. The build workflow preserves the upstream license and adds a modification notice.
