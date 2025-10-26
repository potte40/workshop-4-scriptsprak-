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

# SETTINGS

$auditPath = Join-Path -Path $PSScriptRoot -ChildPath "network_configs"
$reportPath = Join-Path -Path $PSScriptRoot -ChildPath "security_audit.txt"
$backupRoot = Join-Path -Path $auditPath -ChildPath "backups"

### FILE INVENTORY Räknare ###

$allFiles = Get-ChildItem -Path $auditPath -Recurse -File
$configFiles = $allFiles | Where-Object { $_.Extension -match "^\.(conf|rules)$" }
$logFiles = $allFiles | Where-Object { $_.Extension -eq ".log" }
$backupFiles = $allFiles | Where-Object { $_.Extension -eq ".bak" }

$recentFiles = $allFiles | Where-Object {
    $_.LastWriteTime -ge $weekAgo -and $_.LastWriteTime -le $now
} | Sort-Object LastWriteTime -Descending

### LOG ANALYSIS Räknare ###

$logErrors = @{}           
$failedPerIP = @{}        
$errorCategories = @{
    "Authentication failures" = 0
    "Interface down events"   = 0
    "Service failures"        = 0
}
$ipPattern = '\b\d{1,3}(\.\d{1,3}){3}\b'

foreach ($log in $logFiles) {
    $content = Get-Content $log.FullName

    # Räkna ERROR per fil
    $errorMatches = $content | Select-String -Pattern "ERROR"
    if ($errorMatches.Count -gt 0) { $logErrors[$log.Name] = $errorMatches.Count }

    # Hitta FAILED LOGIN och hitta IP
    $failedMatches = $content | Select-String -Pattern "LOGIN FAIL" -SimpleMatch
    foreach ($match in $failedMatches) {
        $ips = ($match.Line | Select-String -Pattern $ipPattern -AllMatches).Matches.Value
        if (-not $ips) { $ips = "unknown" }
        foreach ($ip in $ips) {
            if ($failedPerIP.ContainsKey($ip)) {
                $failedPerIP[$ip]++
            }
            else {
                $failedPerIP[$ip] = 1
            }
        }
    }

    ### Top Error Categories ###

    # Authentication failures
    $authFails = ($content | Select-String -Pattern "authentication failed").Count
    $errorCategories["Authentication failures"] += $authFails

    # Interface down events
    $interfaceDownPattern = 'ERROR.*Ethernet[\d/]+ down'
    $interfaceDownMatches = $content | Select-String -Pattern $interfaceDownPattern
    $interfaceDownCount = $interfaceDownMatches.Count
    $errorCategories["Interface down events"] += $interfaceDownCount

    # Service failures (alla andra ERRORs)
    $totalErrors = $errorMatches.Count
    $serviceFailures = $totalErrors - $authFails - $interfaceDownCount
    $errorCategories["Service failures"] += $serviceFailures
}


### MISSING BACKUPS ###
$backupIndex = @{}

if (Test-Path $backupRoot) {
    # Hitta backup-mappar 
    $backupDirs = Get-ChildItem -Path $backupRoot -Directory -ErrorAction SilentlyContinue
    foreach ($dir in $backupDirs) {
        # Försök extrahera datum från mappnamn 'backup-YYYY-MM-DD'
        $dirDate = $null
        if ($dir.Name -match 'backup-(\d{4}-\d{2}-\d{2})') {
            try { $dirDate = [datetime]::ParseExact($matches[1], 'yyyy-MM-dd', $null) } catch { $dirDate = $dir.LastWriteTime }
        }
        else {
            # fallback: använd mappens LastWriteTime om inget datum i namnet
            $dirDate = $dir.LastWriteTime
        }

        # Indexera filer i mappen
        Get-ChildItem -Path $dir.FullName -File -ErrorAction SilentlyContinue | ForEach-Object {
            $bakName = $_.Name
            # ta bort .bak-suffix om det finns (t.ex. SW-CORE-01.conf.bak -> SW-CORE-01.conf)
            $origName = if ($bakName -match '\.bak$') { $bakName -replace '\.bak$', '' } else { $bakName }

            # Om vi redan har ett datum för filen, spara det nyaste
            if ($backupIndex.ContainsKey($origName)) {
                if ($dirDate -gt $backupIndex[$origName]) {
                    $backupIndex[$origName] = $dirDate
                }
            }
            else {
                $backupIndex[$origName] = $dirDate
            }
        }
    }
}

# Jämför mot alla konfigurationsfiler i auditPath
$allConfigFiles = $allFiles | Where-Object { $_.Extension -match '^\.(conf|rules)$' }

$missingBackups = @()

foreach ($cfg in $allConfigFiles) {
    $name = $cfg.Name
    if ($backupIndex.ContainsKey($name)) {
        $lastBakDate = $backupIndex[$name]
        # Om senaste backup är äldre än weekAgo → lägg i missing
        if ($lastBakDate -lt $weekAgo) {
            $missingBackups += [PSCustomObject]@{
                Name       = $name
                LastBackup = $lastBakDate.ToString('yyyy-MM-dd')
                Status     = 'older-than-threshold'
            }
        }
        # annars: backup finns och är ny nog — inget att göra
    }
    else {
        # ingen backup hittad alls
        $missingBackups += [PSCustomObject]@{
            Name       = $name
            LastBackup = $null
            Status     = 'no-backup'
        }
    }
}

# Anropa funktion för compare mot baseline
$configPath = Join-Path -Path $PSScriptRoot -ChildPath "network_configs"
$securityDeviations = Compare-WithBaseline -ConfigPath $configPath



# ================================
#             RAPPORT            #
# ================================
$report = @"
===============================================================================
                        SECURITY AUDIT REPORT
===============================================================================
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

$report += "`nLOG ANALYSIS`n------------`n"

$errorsSum = ($logErrors.Values | Measure-Object -Sum).Sum
$report += "Errors in Last 24 Hours: $errorsSum`n`n"

foreach ($logName in $logErrors.Keys) {
    $report += "- ${logName}: $($logErrors[$logName]) errors`n"
}

$failedSum = ($failedPerIP.Values | Measure-Object -Sum).Sum
$report += "`nFailed Login Attempts: $failedSum`n"
foreach ($ip in $failedPerIP.Keys) {
    $report += "- $($failedPerIP[$ip]) attempts from $ip`n"
}

$report += "`nTop Error Categories:`n"
foreach ($category in $errorCategories.Keys) {
    $report += ". ${category}: $($errorCategories[$category])`n"
}

if ($missingBackups.Count -eq 0) {
    $report += "`nMISSING BACKUPS`n---------------`nAll config files have recent backups.`n"
}
else {
    $report += "`nMISSING BACKUPS`n---------------`nFiles without recent backup (>7 days):`n"
    foreach ($m in $missingBackups) {
        $last = if ($m.LastBackup) { $m.LastBackup } else { "no backup found" }
        $report += "- $($m.Name) (last backup: $last)`n"
    }
}

$report += "`nBASELINE COMPLIANCE`n-------------------`n"

$securityDeviations | ForEach-Object {
    $report += "- $($_.File): $($_.Difference)`n"
}

# ================================
#        SKRIVA RAPPORTEN        #
# ================================
$report | Out-File -FilePath $reportPath -Encoding UTF8
Write-Host "Security audit report created at $reportPath"