

#Säkerhetsfunktion
function Find-SecurityIssues {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path, 

        [Parameter()]
        [string[]]$FileTypes = @("*.conf", "*.rules") 
    )

    # Definiera sökmönster
    $patterns = @(
        "enable password",          
        "enable secret",            
        "public",           
        "private"
    )

    $results = @()

    foreach ($ext in $FileTypes) {
        $files = Get-ChildItem -Path $Path -Recurse -File -Filter $ext -ErrorAction SilentlyContinue

        foreach ($file in $files) {
            $foundPasswordOrSecret = $false

        
            $content = Get-Content $file.FullName

            foreach ($pattern in $patterns) {
                $foundmatches = $content | Select-String -Pattern $pattern -SimpleMatch
                foreach ($match in $foundmatches) {
                    $results += [PSCustomObject]@{
                        File       = $file.FullName
                        LineNumber = $match.LineNumber
                        Pattern    = $pattern
                        LineText   = $match.Line.Trim()
                    }

                    # Markera om man hittar enable password eller secret
                    if ($pattern -in @("enable password", "enable secret")) {
                        $foundPasswordOrSecret = $true
                    }
                }
            }

            # Om ingen password/secret hittats, lägg till varning
            if (-not $foundPasswordOrSecret) {
                $results += [PSCustomObject]@{
                    File       = $file.FullName
                    LineNumber = ""
                    Pattern    = "MISSING PASSWORD/SECRET"
                    LineText   = "No 'enable password' or 'enable secret' found"
                }
            }
        }
    }

    return $results
}



# Jämföra mot baseline config

function Compare-WithBaseline {
    param (
        [Parameter(Mandatory = $true)][string]$ConfigPath
    )

    # Nycklar vi vill kontrollera
    $baselineChecks = @(
        "service password-encryption",
        "no ip http server",
        "no ip http secure-server",
        "snmp-server community",
        "logging host",
        "logging trap warnings",
        "ntp server",
        "banner login"
    )

    # Hitta alla .conf-filer i ConfigPath (exkludera baseline-mappen)
    $routerPath = Join-Path -Path $ConfigPath -ChildPath "routers"

    $allConfigFiles = Get-ChildItem -Path $routerPath -File |
    Where-Object { $_.Extension -eq ".conf" -and $_.FullName -notlike "*\baseline\*" }

    $deviations = @()

    foreach ($cfg in $allConfigFiles) {
        $currentContent = Get-Content $cfg.FullName

        foreach ($check in $baselineChecks) {
            if (-not ($currentContent -match [regex]::Escape($check))) {
                $deviations += [PSCustomObject]@{
                    File       = $cfg.Name
                    Difference = $check
                }
            }
        }
    }

    return $deviations
}