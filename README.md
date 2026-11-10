# Face Gate (Android)

This repository contains a standalone Android app that protects access to its own content with either:
- Android system biometrics exposed through BiometricPrompt (face/fingerprint where supported by the device), or
- a locally configured PIN (minimum 6 digits).

## Important security boundary

This is an **in-app gate**. It does not replace, hook, or bypass Android's device lock screen. Root access alone does not make a regular app an Android system authenticator. To make a custom authenticator a real device unlock method, it must be implemented and trusted at the OS/ROM level (for example, as part of a custom system image with the required platform permissions and hardware-backed authentication integration).

The app may report whether common root indicators are present, but it does not use root to take over system authentication.

## Build

Open the project in Android Studio, or run:

```bash
./gradlew assembleDebug
```

The debug APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

For a distributable release APK, configure a private signing key in your own build environment. Never commit a keystore or passwords to this repository.

## Compatibility

- minSdk 29 (Android 10)
- targetSdk 35
- AndroidX BiometricPrompt; available biometric modalities depend on the device and its Android implementation.
