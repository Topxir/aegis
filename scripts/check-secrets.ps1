$ErrorActionPreference = "Stop"

Write-Host "[aegis-secret-scan] Checking repository for leaked secrets and personal metadata..."

$patterns = @(
    "BEGIN (RSA|OPENSSH|EC|PGP|PRIVATE) KEY",
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
    (Test-Path $_)
}

foreach ($pattern in $patterns) {
    foreach ($file in $files) {
        $matchesFound = Select-String -Path $file -Pattern $pattern -CaseSensitive -ErrorAction SilentlyContinue
        if ($matchesFound) {
            Write-Error "[ERROR] Potential secret pattern '$pattern' matched in $file"
            $failed = $true
        }
    }
}

if ($failed) {
    Write-Error "[FAIL] Secret scan failed. Remove sensitive data before committing."
    exit 1
}

Write-Host "[OK] No secrets detected."
