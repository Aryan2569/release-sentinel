<#
.SYNOPSIS
    Deep Git history audit script for Release Sentinel repository.
.DESCRIPTION
    Audits the entire git history (all commits and all trees) for:
    1. All unique author and committer names and emails
    2. 20 largest blobs ever committed (hash, size, path, first commit) + git count-objects -vH
    3. Scans across ALL commits for secret patterns, local paths, and archive/binary extensions
    4. Lists all git tags with annotations/subjects
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "         Release Sentinel - Deep History Audit            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Unique Authors and Committers across full history
Write-Host "`n[1/4] Unique Authors and Committers (Full History)..." -ForegroundColor Yellow
$identities = git log --all --format="%an <%ae> | %cn <%ce>" | Sort-Object -Unique
$identities | ForEach-Object { Write-Host "  $_" }

# 2. .git Size and 20 Largest Blobs Ever Committed
Write-Host "`n[2/4] Repository Object Size & 20 Largest Blobs..." -ForegroundColor Yellow
git count-objects -vH | ForEach-Object { Write-Host "  $_" }

Write-Host "`n  Finding 20 largest blobs across all revisions..." -ForegroundColor DarkGray
$rawObjects = git rev-list --objects --all | git cat-file --batch-check='%(objectname) %(objecttype) %(objectsize) %(rest)'
$blobs = $rawObjects | Where-Object { $_ -match '^[0-9a-f]{40} blob' } | ForEach-Object {
    $parts = $_ -split ' ', 4
    $hash = $parts[0]
    $size = [int64]$parts[2]
    $path = if ($parts.Length -gt 3) { $parts[3] } else { "(no-path)" }
    [PSCustomObject]@{
        Hash = $hash
        SizeBytes = $size
        SizeKB = [math]::Round($size / 1KB, 2)
        SizeMB = [math]::Round($size / 1MB, 2)
        Path = $path
    }
} | Sort-Object SizeBytes -Descending | Select-Object -First 20

$blobs | ForEach-Object {
    $commit = git log --all --find-object=$($_.Hash) --format="%h (%cs): %s" -1
    Write-Host ("  {0,8} KB | {1} | {2} | First commit: {3}" -f $_.SizeKB, $_.Hash.Substring(0,8), $_.Path, $commit)
}

# 3. Secret & Path Scan across ALL History
Write-Host "`n[3/4] Scanning full history for secrets, machine paths, and archives..." -ForegroundColor Yellow

$secretPatterns = @("ghp_", "github_pat_", "npm_", "AKIA", "BEGIN PRIVATE KEY", "password=")
$pathPatterns = @("C:\\Users", "C:\\rs-data", "C:\\My project")
$archiveExtensions = @("\.zip", "\.tgz", "\.tar\.gz", "\.tar", "\.7z", "\.exe")

Write-Host "  Scanning for secret tokens across all revisions..." -ForegroundColor DarkGray
foreach ($pat in $secretPatterns) {
    $matches = git log --all -S "$pat" --oneline
    if ($matches) {
        Write-Host "  [!] MATCH for secret pattern '$pat':" -ForegroundColor Red
        $matches | ForEach-Object { Write-Host "      $_" -ForegroundColor Red }
    } else {
        Write-Host "  [OK] No occurrences of '$pat'" -ForegroundColor Green
    }
}

Write-Host "  Scanning for absolute local paths across all revisions..." -ForegroundColor DarkGray
foreach ($pat in $pathPatterns) {
    $matches = git log --all -S "$pat" --oneline
    if ($matches) {
        Write-Host "  [!] Found absolute path pattern '$pat':" -ForegroundColor Magenta
        $matches | Select-Object -First 5 | ForEach-Object { Write-Host "      $_" -ForegroundColor Magenta }
        if ($matches.Count -gt 5) {
            Write-Host "      ... and $($matches.Count - 5) more commits" -ForegroundColor Magenta
        }
    } else {
        Write-Host "  [OK] No occurrences of '$pat'" -ForegroundColor Green
    }
}

Write-Host "  Scanning for archive and executable blobs in history..." -ForegroundColor DarkGray
$foundArchives = $rawObjects | Where-Object {
    $line = $_
    $archiveExtensions | Where-Object { $line -match "$($_)($|\s)" }
}
if ($foundArchives) {
    Write-Host "  [!] Found archive/binary objects in history:" -ForegroundColor Magenta
    $foundArchives | ForEach-Object { Write-Host "      $_" -ForegroundColor Magenta }
} else {
    Write-Host "  [OK] No archive/executable blobs found in object database." -ForegroundColor Green
}

# 4. Git Tags List
Write-Host "`n[4/4] Listing all git tags..." -ForegroundColor Yellow
$tags = git tag -n -l
$tags | ForEach-Object { Write-Host "  $_" }

Write-Host "`nHistory audit complete." -ForegroundColor Cyan
