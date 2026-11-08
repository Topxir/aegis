param(
    [switch]$SkipAndroid,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

# dlltool setup
$dlltoolOnPath = $null -ne (Get-Command dlltool -ErrorAction SilentlyContinue)

if (-not $dlltoolOnPath) {
    $sysroot = & rustc +stable-x86_64-pc-windows-gnu --print sysroot
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to get rustc sysroot"
    }

    $llvmArPath = Join-Path $sysroot "lib\rustlib\x86_64-pc-windows-gnu\bin\llvm-ar.exe"
    if (-not (Test-Path $llvmArPath)) {
        throw "llvm-ar.exe not found at $llvmArPath"
    }

    $toolsDir = Join-Path $env:USERPROFILE ".aegis-tools\bin"
    $dlltoolPath = Join-Path $toolsDir "dlltool.exe"

    if (-not (Test-Path $toolsDir)) {
        New-Item -ItemType Directory -Path $toolsDir -Force | Out-Null
    }

    Copy-Item -Path $llvmArPath -Destination $dlltoolPath -Force
    $env:PATH = "$toolsDir;$env:PATH"
}

# Run tests unless skipped
if (-not $SkipTests) {
    Write-Host "Running tests..."
    & cargo +stable-x86_64-pc-windows-gnu test --workspace
    if ($LASTEXITCODE -ne 0) {
        throw "Tests failed"
    }

    Write-Host "Running clippy..."
    & cargo +stable-x86_64-pc-windows-gnu clippy --workspace --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) {
        throw "Clippy found warnings"
    }
}

# Build Windows binaries
Write-Host "Building release binaries..."
& cargo +stable-x86_64-pc-windows-gnu build --release -p aegis-ui-desktop -p aegis-server
if ($LASTEXITCODE -ne 0) {
    throw "Cargo build failed"
}

# Copy desktop binary
$desktopDestDir = Join-Path $root "builds\desktop"
if (-not (Test-Path $desktopDestDir)) {
    New-Item -ItemType Directory -Path $desktopDestDir -Force | Out-Null
}
$desktopSource = Join-Path $root "target\release\aegis-desktop.exe"
$desktopDest = Join-Path $desktopDestDir "aegis-desktop.exe"
Copy-Item -Path $desktopSource -Destination $desktopDest -Force

# Bundle the official Tor client next to the desktop binary
$torSource = Join-Path $env:USERPROFILE ".aegis-tools\tor\tor"
$torDest = Join-Path $desktopDestDir "tor"
if (-not (Test-Path (Join-Path $torSource "tor.exe"))) {
    throw "tor.exe not found in $torSource"
}
if (Test-Path $torDest) {
    Remove-Item -Path $torDest -Recurse -Force
}
New-Item -ItemType Directory -Path $torDest -Force | Out-Null
Copy-Item -Path (Join-Path $torSource "*") -Destination $torDest -Recurse -Force

# Copy server binary
$serverDestDir = Join-Path $root "builds\server"
if (-not (Test-Path $serverDestDir)) {
    New-Item -ItemType Directory -Path $serverDestDir -Force | Out-Null
}
$serverSource = Join-Path $root "target\release\aegis-serverd.exe"
$serverDest = Join-Path $serverDestDir "aegis-serverd.exe"
Copy-Item -Path $serverSource -Destination $serverDest -Force

# Copy WebView2Loader.dll if it exists
$webview2Source = Join-Path $root "target\release\WebView2Loader.dll"
if (Test-Path $webview2Source) {
    $webview2Dest = Join-Path $desktopDestDir "WebView2Loader.dll"
    Copy-Item -Path $webview2Source -Destination $webview2Dest -Force
}

# Build Android unless skipped
if (-not $SkipAndroid) {
    Write-Host "Building Android..."

    # Set JAVA_HOME if not set and C:\jdk17 exists
    if ([string]::IsNullOrEmpty($env:JAVA_HOME) -and (Test-Path "C:\jdk17")) {
        $env:JAVA_HOME = "C:\jdk17"
    }

    $androidDir = Join-Path $root "apps\aegis-android"
    try {
        Push-Location $androidDir
        & .\gradlew.bat testDebugUnitTest assembleRelease
        if ($LASTEXITCODE -ne 0) {
            throw "Gradle build failed"
        }
    }
    finally {
        Pop-Location
    }

    $androidDestDir = Join-Path $root "builds\android-apk"
    if (-not (Test-Path $androidDestDir)) {
        New-Item -ItemType Directory -Path $androidDestDir -Force | Out-Null
    }

    $apkSource = Join-Path $androidDir "app\build\outputs\apk\release\app-release.apk"
    if (Test-Path $apkSource) {
        $apkDest = Join-Path $androidDestDir "aegis-messenger-release.apk"
        Copy-Item -Path $apkSource -Destination $apkDest -Force
    }
    else {
        $unsignedSource = Join-Path $androidDir "app\build\outputs\apk\release\app-release-unsigned.apk"
        if (Test-Path $unsignedSource) {
            $unsignedDest = Join-Path $androidDestDir "aegis-messenger-release-unsigned.apk"
            Copy-Item -Path $unsignedSource -Destination $unsignedDest -Force
            Write-Warning "Signing material not found (~\.aegis-release\keystore.properties or env AEGIS_KEYSTORE_PROPERTIES); copied unsigned APK"
        }
    }
}

# Signed update: manifest and files for the server's <data-dir>/update
$updateKey = if ($env:AEGIS_UPDATE_KEY) { $env:AEGIS_UPDATE_KEY } else { Join-Path $env:USERPROFILE ".aegis-update.key" }
if (Test-Path $updateKey) {
    Write-Host "Signing update manifest..."
    $updateDir = Join-Path $root "builds\update"
    $version = (Select-String -Path (Join-Path $root "Cargo.toml") -Pattern '^version = "(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
    # Seconds since 1970 keep the sequence growing even if builds/update was emptied.
    $seq = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $signArgs = @("sign", "--key", $updateKey, "--out", $updateDir, "--version", $version, "--seq", "$seq", "--windows", $desktopDest)
    $apk = Join-Path $root "builds\android-apk\aegis-messenger-release.apk"
    if (-not $SkipAndroid -and (Test-Path $apk)) {
        $gradle = Get-Content (Join-Path $root "apps\aegis-android\app\build.gradle.kts") -Raw
        $code = [regex]::Match($gradle, 'versionCode = (\d+)').Groups[1].Value
        $apkVersion = [regex]::Match($gradle, 'versionName = "([^"]+)"').Groups[1].Value
        $signArgs += @("--android", $apk, "--android-code", $code, "--android-version", $apkVersion)
    }
    & (Join-Path $root "target\release\aegis-update.exe") @signArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Signing the update failed"
    }
}
else {
    Write-Warning "Update key not found ($updateKey); no signed update written"
}

# Generate SHA256SUMS.txt
Write-Host "Generating checksums..."

$sumsFile = Join-Path $root "builds\SHA256SUMS.txt"
$sumsContent = @()

$filesToHash = @(
    (Join-Path $root "builds\android-apk\*.apk"),
    (Join-Path $root "builds\desktop\aegis-desktop.exe"),
    (Join-Path $root "builds\desktop\WebView2Loader.dll"),
    (Join-Path $root "builds\desktop\tor\tor.exe"),
    (Join-Path $root "builds\server\aegis-serverd.exe")
)

foreach ($pattern in $filesToHash) {
    $files = @(Get-Item -Path $pattern -ErrorAction SilentlyContinue)
    foreach ($file in $files) {
        $hash = (Get-FileHash -Path $file.FullName -Algorithm SHA256).Hash.ToLower()
        $relativePath = $file.FullName.Substring($root.Length + 1)
        $relativePath = $relativePath.Replace('\', '/')
        $sumsContent += "$hash  $relativePath"
    }
}

# Get-FileHash order is stable; LF endings so the file verifies with sha256sum -c on any OS.
$text = if ($sumsContent.Count -gt 0) { ($sumsContent -join "`n") + "`n" } else { "" }
[System.IO.File]::WriteAllText($sumsFile, $text, [System.Text.UTF8Encoding]::new($false))

# Summary
Write-Host ""
Write-Host "Build complete. Artifacts:"
Write-Host "  Windows:  builds/desktop/aegis-desktop.exe"
Write-Host "  Server:   builds/server/aegis-serverd.exe"
if (-not $SkipAndroid) {
    Write-Host "  Android:  builds/android-apk/aegis-messenger-release.apk (or -unsigned.apk)"
}
Write-Host "  Checksums: builds/SHA256SUMS.txt"
if (Test-Path (Join-Path $root "builds\update\manifest.signed")) {
    Write-Host "  Update:    builds/update/ (copy into the server's <data-dir>/update)"
}
