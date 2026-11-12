# Builds

This folder contains prebuilt artifacts.

- `android-apk/aegis-messenger-release.apk` - Android client. It is larger than GitHub's 100 MB file limit, so it is not stored in git: download it from the GitHub Release of the same tag. Its checksum is in `SHA256SUMS.txt`.
- `desktop/aegis-desktop.exe` - Windows desktop client
- `SHA256SUMS.txt` - SHA256 checksums for the artifacts above

To verify checksums from the repository root:

```sh
sha256sum -c SHA256SUMS.txt
```

On Windows, you can check a file with:

```powershell
Get-FileHash <file> -Algorithm SHA256
```

## Building

The artifacts are produced by `scripts/build.ps1`.

```powershell
powershell -ExecutionPolicy Bypass -File scripts/build.ps1 [-SkipAndroid] [-SkipTests]
```

- `-SkipTests` - skips running the Rust workspace tests (`cargo +stable-x86_64-pc-windows-gnu test --workspace`) and Clippy (`cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings`) before building the Windows binaries.
- `-SkipAndroid` - skips the Android build (`gradlew testDebugUnitTest assembleRelease`) and skips copying the APK into `builds/android-apk/`.

Without flags, the script builds the Windows binaries, builds Android, and regenerates `SHA256SUMS.txt`.
