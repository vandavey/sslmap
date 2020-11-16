# Conmand-line arguments
[CmdletBinding()]
param (
    [Parameter()]
    [Alias("h")]
    [switch]$help = $false
)

$title = "SSLMap Installer"
Write-Output ($title + "`n" + ("-" * $title.Length))

# TODO: Complete and debug...
