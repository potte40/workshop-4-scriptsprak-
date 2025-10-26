# Anropa functions-filen
. "$PSScriptRoot\functions.ps1"





Get-ChildItem -Path "network_configs" -Recurse -Include *.conf, *.rules, *.log

$now = Get-Date "2024-10-14"
$weekAgo = $now.AddDays(-7)

Get-ChildItem -Path "network_configs" -Recurse |
Where-Object { $_.LastWriteTime -gt $weekAgo } |
Sort-Object LastWriteTime



$byFileType = Get-ChildItem -File -Path "network_configs" -Recurse |
Group-Object -Property Extension

Write-Host "FILTYPER, ANTAL OCH TOTAL STORLEK (i bytes)"
Write-Host ("-" * 60)

foreach ($type in $byFileType) {
    $totalSize = ($type.Group | Measure-Object -Property Length -Sum).Sum
    Write-Host "Filändelse: $($type.Name) | Antal: $($type.Count) | Total storlek: $totalSize bytes"
}


Get-ChildItem -Path "network_configs" -Recurse -Filter "*.log" -File |
Sort-Object -Property Length -Descending |
Select-Object -First 5 Name, Length

# Hitta alla .conf-filer och sök efter IP-adresser
$ips = Get-ChildItem -Path "network_configs" -Recurse -Filter "*.conf" -File |
Select-String -Pattern "\b\d{1,3}(\.\d{1,3}){3}\b" |
ForEach-Object { $_.Matches.Value } |
Sort-Object -Unique

# Visa unika IP-adresser
Write-Host "Unika IP-adresser funna i .conf-filer:"
Write-Host $("-" * 40)
$ips


$results = Get-ChildItem -Path "network_configs" -Recurse -Filter "*.log" -File |
Select-String -Pattern "ERROR", "FAILED", "DENIED" -SimpleMatch |
Group-Object -Property Path | 
Select-Object @{Name = "Fil"; Expression = { $_.Name } },
@{Name = "Antal träffar"; Expression = { $_.Count } }

# Visa resultatet
Write-Host "Säkerhetsproblem i loggfiler:"
Write-Host $("-" * 50)
$results | ForEach-Object {
    Write-Host "Fil: $($_.Fil) — $($_."Antal träffar") träffar"
}


# Hitta alla konfigurationsfiler (.conf, .rules, .log)
$configFiles = Get-ChildItem -Path "network_configs" -Recurse -File |
Where-Object { $_.Extension -in ".conf", ".rules" } |
Select-Object Name,
@{Name = "FullPath"; Expression = { $_.FullName } },
@{Name = "SizeBytes"; Expression = { $_.Length } },
LastWriteTime

# Exportera till CSV
$configFiles | Export-Csv -Path "$PSScriptRoot\config_inventory.csv" -NoTypeInformation -Encoding UTF8

Write-Host "`nCSV-fil skapad: config_inventory.csv"

# Anropa funktionen för säkerhetsgranskning
$securityIssues = Find-SecurityIssues -Path "network_configs"

$securityIssues | Export-Csv -Path "$PSScriptRoot\security_issues.csv" -NoTypeInformation -Encoding UTF8

# Gruppera efter kategori
$weakPasswords = $securityIssues | Where-Object { $_.LineText -match "(?i)enable password|username.*secret" }
$defaultSNMP = $securityIssues | Where-Object { $_.LineText -match "(?i)snmp-server community (public|private)" }
$missingEncryption = $securityIssues | Where-Object { $_.LineText -match "(?i)HTTP allowed without HTTPS|service password-encryption" }

$totalIssues = $weakPasswords.Count + $defaultSNMP.Count + $missingEncryption.Count

# ================================
# SETTINGS
# ================================
$auditPath = Join-Path -Path $PSScriptRoot -ChildPath "network_configs"
$backupPath = Join-Path -Path $auditPath -ChildPath "backup"
$reportPath = Join-Path -Path $PSScriptRoot -ChildPath "security_audit.txt"

# ================================
# FILE INVENTORY
# ================================
$allFiles = Get-ChildItem -Path $auditPath -Recurse -File
$configFiles = $allFiles | Where-Object { $_.Extension -match "^\.(conf|rules)$" }
$logFiles = $allFiles | Where-Object { $_.Extension -eq ".log" }
$backupFiles = $allFiles | Where-Object { $_.Extension -eq ".bak" }

$recentFiles = $allFiles | Where-Object {
    $_.LastWriteTime -ge $weekAgo -and $_.LastWriteTime -le $now
} | Sort-Object LastWriteTime -Descending

# ================================
# LOG ANALYSIS
# ================================
$logErrors = @{}
$failedLogins = @{}

foreach ($log in $logFiles) {
    $errorCount = (Select-String -Path $log.FullName -Pattern "ERROR").Count
    $failCount = (Select-String -Path $log.FullName -Pattern "FAILED").Count

    if ($errorCount -gt 0) { $logErrors[$log.Name] = $errorCount }
    if ($failCount -gt 0) { $failedLogins[$log.Name] = $failCount }
}

# ================================
# MISSING BACKUPS
# ================================
$missingBackups = $backupfiles | Where-Object {
    $backupFile = Join-Path -Path $backupPath -ChildPath $_.Name
    (-not (Test-Path $backupFile)) -or ((Get-Item $backupFile).LastWriteTime -lt $weekAgo)
}

# ================================
# GENERATE REPORT
# ================================
$report = @"
================================================================================
                    SECURITY AUDIT REPORT
================================================================================
Generated: $($now.ToString("yyyy-MM-dd HH:mm:ss"))
Audit Path: $auditPath

FILE INVENTORY
--------------
Total Files: $($allFiles.Count)
Config Files: $($configFiles.Count)
Log Files: $($logFiles.Count)
Backup Files: $($backupFiles.Count)

Files Modified Last 7 Days: $($recentFiles.Count)
------------------------------

"@

foreach ($f in $recentFiles) {
    $report += "- $($f.Name) ($($f.LastWriteTime.ToString("yyyy-MM-dd")))`n"
}

$report += "`nSECURITY FINDINGS
-----------------
Critical Issues Found: $totalIssues
"

if ($weakPasswords.Count -gt 0) {
    $report += "`n. Weak Passwords Detected:`n"
    foreach ($issue in $weakPasswords) {
        $fileName = Split-Path $issue.File -Leaf
        $report += "   - $($fileName) `"$($issue.LineText)`" (line $($issue.LineNumber))`n"
    }
}

if ($defaultSNMP.Count -gt 0) {
    $report += "`n. Default SNMP Communities:`n"
    foreach ($issue in $defaultSNMP) {
        $fileName = Split-Path $issue.File -Leaf
        $report += "   - $($fileName) `"$($issue.LineText)`" (line $($issue.LineNumber))`n"
    }
}

if ($missingEncryption.Count -gt 0) {
    $report += "`n. Missing Encryption:`n"
    foreach ($issue in $missingEncryption) {
        $fileName = Split-Path $issue.File -Leaf
        $report += "   - $($fileName): `"$($issue.LineText)`" (line $($issue.LineNumber))`n"
    }
}
# ================================
# LOG ANALYSIS REPORT
# ================================
$report += "`nLOG ANALYSIS
------------
Errors in Last 24 Hours: $($logErrors.Values | Measure-Object -Sum).Sum
"

foreach ($key in $logErrors.Keys) {
    $report += "- $($key): $($logErrors[$key]) errors`n"
}

$report += "`nFailed Login Attempts:`n"
foreach ($key in $failedLogins.Keys) {
    $report += "- $($key): $($failedLogins[$key]) failed attempts`n"
}

# ================================
# MISSING BACKUPS
# ================================
$report += "`nMISSING BACKUPS
---------------
Files without recent backup (>7 days):`n"

foreach ($missing in $missingBackups) {
    $backupFile = Join-Path $backupPath $missing.Name
    $lastBackup = if (Test-Path $backupFile) { (Get-Item $backupFile).LastWriteTime.ToString("yyyy-MM-dd") } else { "no backup found" }
    $report += "- $($missing.Name) (last backup: $lastBackup)`n"
}

# ================================
# SAVE REPORT
# ================================
$report | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "Security audit report created at $reportPath"



