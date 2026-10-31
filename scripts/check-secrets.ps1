$ErrorActionPreference = "Stop"

Write-Host "[aegis-secret-scan] Checking repository for leaked secrets and personal metadata..."

$patterns = @(
    "BEGIN ([A-Z0-9]+ )?PRIVATE KEY",
    "BEGIN PGP PRIVATE KEY BLOCK",
    "AKIA[0-9A-Z]{16}",
    "ghp_[0-9a-zA-Z]{36}",
    "github_pat_[0-9a-zA-Z_]{82}",
    "xox[baprs]-[0-9a-zA-Z-]{10,48}",
    "sk-[a-zA-Z0-9]{32,}"
)

$failed = $false
$files = git ls-files | Where-Object {
    $_ -ne "scripts/check-secrets.ps1" -and
    $_ -ne "scripts/check-secrets.sh" -and
    $_ -notmatch '\.(apk|aab|exe|dll|so|dylib|jar|zip|png|jpg|jpeg|gif|ico|webp)$' -and
    (Test-Path -LiteralPath $_)
}

foreach ($pattern in $patterns) {
    foreach ($file in $files) {
        $matchesFound = Select-String -LiteralPath $file -Pattern $pattern -CaseSensitive -Encoding utf8 -ErrorAction SilentlyContinue
        if ($matchesFound) {
            Write-Host "[ERROR] Potential secret pattern '$pattern' matched in $file" -ForegroundColor Red
            $failed = $true
        }
    }
}

if ($failed) {
    Write-Host "[FAIL] Secret scan failed. Remove sensitive data before committing." -ForegroundColor Red
    exit 1
}

Write-Host "[OK] No secrets detected."
