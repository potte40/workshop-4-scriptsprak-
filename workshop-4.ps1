
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
Select-String -Pattern '\b\d{1,3}(\.\d{1,3}){3}\b' |
ForEach-Object { $_.Matches.Value } |
Sort-Object -Unique

# Visa unika IP-adresser
Write-Host "Unika IP-adresser funna i .conf-filer:"
Write-Host $("-" * 40)
$ips