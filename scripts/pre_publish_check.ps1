<#
.SYNOPSIS
    Pre-publish audit script for Release Sentinel repository.
.DESCRIPTION
    Verifies that the repository is clean, lean, safe, and self-contained before publishing:
    - Repository size and 30 largest tracked files
    - No large files (> 10 MB)
    - No forbidden binaries, sample archives (.zip/.tgz), cache, or logs
    - Secret and token scan (GitHub PATs, npm tokens, AWS keys, private keys)
    - No hardcoded local drive paths (C:\Users, C:\rs-data, C:\My project)
    - Essential project files present (LICENSE, SECURITY.md, CONTRIBUTING.md, CHANGELOG.md, README.md)
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         Release Sentinel - Pre-Publish Repo Audit        " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$hasErrors = $false

# 1. Total Repository Size
Write-Host "`n[1/5] Checking repository size..." -ForegroundColor Yellow
$countObj = git count-objects -vH
$countObj | ForEach-Object { Write-Host "  $_" }

# 2. 30 Largest Tracked Files
Write-Host "`n[2/5] Inspecting 30 largest tracked files..." -ForegroundColor Yellow
$trackedFiles = git ls-files | ForEach-Object {
    if (Test-Path $_ -PathType Leaf) {
        $item = Get-Item $_
        [PSCustomObject]@{
            Path = $_
            SizeBytes = $item.Length
            SizeKB = [math]::Round($item.Length / 1KB, 2)
            SizeMB = [math]::Round($item.Length / 1MB, 2)
        }
    }
} | Sort-Object SizeBytes -Descending

$trackedFiles | Select-Object -First 30 | ForEach-Object {
    $formattedSize = "{0,8:N2} KB" -f $_.SizeKB
    Write-Host "  $formattedSize  $($_.Path)"
}

# Check for files > 10 MB
$over10MB = $trackedFiles | Where-Object { $_.SizeBytes -gt 10MB }
if ($over10MB) {
    Write-Host "  [FAIL] Tracked files exceed 10 MB ceiling:" -ForegroundColor Red
    $over10MB | ForEach-Object { Write-Host "    $($_.Path) ($($_.SizeMB) MB)" -ForegroundColor Red }
    $hasErrors = $true
} else {
    Write-Host "  [PASS] All tracked files are well under 10 MB ceiling." -ForegroundColor Green
}

# 3. Forbidden File Extensions and Paths
Write-Host "`n[3/5] Checking for forbidden archives, cache, and log files..." -ForegroundColor Yellow
$forbidden = git ls-files | Where-Object {
    $_ -match '\.(zip|tgz|tar\.gz|log)$' -or
    $_ -match '^data/cache' -or
    $_ -match 'sample.*\.zip'
}

if ($forbidden) {
    Write-Host "  [FAIL] Forbidden tracked files detected:" -ForegroundColor Red
    $forbidden | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    $hasErrors = $true
} else {
    Write-Host "  [PASS] No .zip, .tgz, data/cache, or log files tracked." -ForegroundColor Green
}

# 4. Secret & Hardcoded Path Scan
Write-Host "`n[4/5] Scanning tracked files for secrets and hardcoded paths..." -ForegroundColor Yellow
$secretHits = python -c "
import subprocess, re
from pathlib import Path

tracked = subprocess.check_output(['git', 'ls-files'], text=True, encoding='utf-8').splitlines()

PATTERNS = {
    'github_pat': re.compile(r'ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}'),
    'npm_token': re.compile(r'npm_[a-zA-Z0-9]{30,}'),
    'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
    'hardcoded_path': re.compile(r'[a-zA-Z]:\\\\(?:Users|rs-data|My project)'),
}

findings = []
for f in tracked:
    p = Path(f)
    if not p.is_file():
        continue
    # Exclude audit scripts themselves from path-pattern self-matches
    if f.endswith('pre_publish_check.ps1') or f.endswith('history_audit.ps1'):
        continue
    try:
        content = p.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        continue
    for p_name, pat in PATTERNS.items():
        matches = pat.findall(content)
        if matches:
            findings.append((f, p_name, matches[:2]))

for f, p_name, m in findings:
    print(f'{f}|{p_name}|{m}')
"

if ($secretHits) {
    Write-Host "  [FAIL] Suspicious patterns found in tracked files:" -ForegroundColor Red
    $secretHits | ForEach-Object {
        $parts = $_ -split '\|'
        Write-Host "    File: $($parts[0]) - Pattern: $($parts[1]) - Sample: $($parts[2])" -ForegroundColor Red
    }
    $hasErrors = $true
} else {
    Write-Host "  [PASS] Zero tokens, secrets, or hardcoded paths found." -ForegroundColor Green
}

# 5. Required Community & Project Files
Write-Host "`n[5/5] Verifying required community and packaging files..." -ForegroundColor Yellow
$requiredFiles = @("LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", "README.md", "pyproject.toml", "action.yml")
foreach ($rf in $requiredFiles) {
    if (Test-Path $rf) {
        Write-Host "  [PASS] $rf is present." -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] $rf is missing!" -ForegroundColor Red
        $hasErrors = $true
    }
}

Write-Host "`n----------------------------------------------------------"
if ($hasErrors) {
    Write-Host "Audit Result: FAILED. Please resolve the errors above." -ForegroundColor Red
    exit 1
} else {
    Write-Host "Audit Result: PASSED cleanly! Repository is ready for publication." -ForegroundColor Green
    exit 0
}
