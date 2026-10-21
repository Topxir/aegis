#!/usr/bin/env bash
set -euo pipefail

echo "[aegis-secret-scan] Checking repository for leaked secrets and personal metadata..."

# Patterns that must never appear in tracked source files
SECRET_PATTERNS=(
  "BEGIN (RSA|OPENSSH|EC|PGP|PRIVATE) KEY"
  "AKIA[0-9A-Z]{16}"
  "ghp_[0-9a-zA-Z]{36}"
  "github_pat_[0-9a-zA-Z_]{82}"
  "xox[baprs]-[0-9a-zA-Z-]{10,48}"
  "sk-[a-zA-Z0-9]{32,}"
)

FAILED=0

for pattern in "${SECRET_PATTERNS[@]}"; do
  if git grep -I -E -e "$pattern" -- ':!scripts/check-secrets.sh' ':!scripts/check-secrets.ps1' ':!*.apk' ':!*.exe' ':!*.jar' >/dev/null 2>&1; then
    echo "[ERROR] Potential secret pattern matched: $pattern"
    git grep -I -n -E -e "$pattern" -- ':!scripts/check-secrets.sh' ':!scripts/check-secrets.ps1' ':!*.apk' ':!*.exe' ':!*.jar'
    FAILED=1
  fi
done

if [ "$FAILED" -ne 0 ]; then
  echo "[FAIL] Secret scan failed. Remove sensitive data before committing."
  exit 1
fi

echo "[OK] No secrets detected."
