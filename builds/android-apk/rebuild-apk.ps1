$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Write-Host "Rebuilding Aegis Android APKs from $repoRoot\apps\aegis-android..."
& "$repoRoot\apps\aegis-android\gradlew.bat" -p "$repoRoot\apps\aegis-android" assembleDebug assembleRelease --no-daemon
Copy-Item "$repoRoot\apps\aegis-android\app\build\outputs\apk\release\app-release.apk" "$PSScriptRoot\aegis-messenger-release.apk" -Force
Copy-Item "$repoRoot\apps\aegis-android\app\build\outputs\apk\debug\app-debug.apk" "$PSScriptRoot\aegis-messenger-debug.apk" -Force
Write-Host "Updated aegis-messenger-release.apk and aegis-messenger-debug.apk in $PSScriptRoot"
