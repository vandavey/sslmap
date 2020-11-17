# Conmand-line arguments
[CmdletBinding()]
param (
    [Parameter()]
    [Alias("h")]
    [switch]$help = $false
)

# Display error message and exit
function HandleError([string]$errMsg) {
    [Console]::ForegroundColor = "red"
    [Console]::Error.WriteLine("[x] $errMsg`n")
    [Console]::ResetColor()
    exit
}

$title = "`nSSLMap Installer"
Write-Output ($title + "`n" + ("-" * $title.Length))

HandleError("The installer script is still in development")
# TODO: Complete implementation and debug...
