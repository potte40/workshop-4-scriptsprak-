

function Find-SecurityIssues {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,          # Basmappen att söka i

        [Parameter()]
        [string[]]$FileTypes = @("*.conf", "*.rules", "*.log")  # Filtyper att söka i
    )

    # Definiera sökmönster
    $patterns = @(
        "password",          
        "secret",            
        "public",           
        "private",
        "enable password"    
    )

    $results = @()

    foreach ($ext in $FileTypes) {
        $files = Get-ChildItem -Path $Path -Recurse -File -Filter $ext
        foreach ($file in $files) {
            foreach ($pattern in $patterns) {
                # Använd Select-String för att söka efter mönster
                $matches = Select-String -Path $file.FullName -Pattern $pattern -SimpleMatch
                foreach ($match in $matches) {
                    $results += [PSCustomObject]@{
                        File       = $file.FullName
                        LineNumber = $match.LineNumber
                        Pattern    = $pattern
                        LineText   = $match.Line.Trim()
                    }
                }
            }
        }
    }

    return $results
}
