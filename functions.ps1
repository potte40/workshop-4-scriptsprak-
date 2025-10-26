

function Find-SecurityIssues {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path, 

        [Parameter()]
        [string[]]$FileTypes = @("*.conf", "*.rules", "*.log")
    )

    # Definiera sökmönster
    $patterns = @(
        "password",          
        "secret",            
        "public",           
        "private"    
    )

    $results = @()

    foreach ($ext in $FileTypes) {
        $files = Get-ChildItem -Path $Path -Recurse -File -Filter $ext
        foreach ($file in $files) {
            foreach ($pattern in $patterns) {
                # Använd Select-String för att söka efter mönster
                $foundmatches = Select-String -Path $file.FullName -Pattern $pattern -SimpleMatch
                foreach ($match in $foundmatches) {
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
