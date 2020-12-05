# SSLMap PowerShell Installer
# ===========================
#  URI: https://raw.githubusercontent.com/vandavey/sslmap/master/install.ps1

# Display error message and exit
function HandleError([string]$ErrorMsg) {
    [Console]::ForegroundColor = "red"
    [Console]::Error.WriteLine("[x] $ErrorMsg`n")
    [Console]::ResetColor()
    exit
}

$title = "SSLMap Installer"
Write-Output ("`n$title`n" + ("-" * $title.Length))

# Executable dependencies
$deps = @(
    [PSCustomObject]@{ # Nmap
        Exe = "nmap.exe"
        OutPath = "$env:USERPROFILE/Downloads/nmap-7.91-setup.exe"
        Uri = "https://nmap.org/dist/nmap-7.91-setup.exe"
    },
    [PSCustomObject]@{ # Python
        Exe = "python.exe"
        OutPath = "$env:USERPROFILE/Downloads/python-3.8.3-amd64.exe"
        Uri = "https://www.python.org/ftp/python/3.8.3/python-3.8.3-amd64.exe"
    }
)

# Download/install missing dependencies
foreach ($dep in $deps) {
    Write-Output "[*] Checking for dependency '$($dep.Exe)'..."
    & $dep.Exe -V 2>$1 | Out-Null

    # Check if last command was successful
    if ($?) {
        Write-Output "[*] Dependency '$($dep.Exe)' already satisfied."
        continue
    }
    $httpHead = @{Uri = $dep.Uri; Method = "HEAD"}

    # Initiate the web request
    try {
        if ((Invoke-WebRequest @httpHead).StatusCode -ne 200) {
            HandleError("Unable to connect to '$($dep.Uri)'")
        }

        Write-Output "[*] Downloading installer for '$($dep.Exe)'..."
        Invoke-WebRequest $dep.Uri -Method "GET" -OutFile $dep.OutPath

        # Run downloaded installer
        if (-not (Test-Path $dep.OutPath)) {
            HandleError("Unable to locate path '$($dep.OutPath)'")
        }
        Write-Output "[*] Launching installer for '$($dep.Exe)...'"

        Start-Process $dep.OutPath -Verb "RunAs" -Wait
        & $dep.Exe -V 2>$1 | Out-Null  # Check if installed

        if (-not $?) {
            HandleError("Unknown error occurred running '$($dep.OutPath)'")
        }
    }
    catch {
        HandleError((Get-Error).Exception.Message)
    }
}

# Pip package installation
try {
    Write-Output "[*] Installing required pip packages..."
    $procArgs = "python.exe -m pip install -U pip XmlToDict3"
    Start-Process powershell.exe $procArgs -Verb "RunAs" -Wait
}
catch {
    HandleError((Get-Error).Exception.Message)
}

Write-Output @"
[*] Dependency 'XMLToDict3' now satisfied.
[*] All dependencies are now satisfied!
[*] Cloning SSLMap GitHub repository...
"@

$outPath = "$env:LOCALAPPDATA\sslmap"
$zipPath = "$env:USERPROFILE\Downloads\sslmap.zip"
$uri = "https://github.com/vandavey/sslmap/archive/master.zip"

# Download and install SSLMap
try {
    # Check for HTTP 200 status code
    if ((Invoke-WebRequest $uri -Method "HEAD").StatusCode -ne 200) {
        HandleError("Unable to connect to '$uri'")
    }
    Invoke-WebRequest $uri -Method "GET" -OutFile $zipPath

    if (-not (Test-Path $zipPath)) {
        HandleError("Unable to locate path '$zipPath'")
    }
    
    Write-Output "[*] Extractring contents to '$outPath'..."
    Expand-Archive $zipPath $outPath -Force
    
    # Check for successful extraction
    if (-not (Test-Path $outPath)) {
        HandleError("Error occurred unpacking writing to $outPath")
    }
    Write-Output "[*] Removing temporary files..."

    # Remove unnecessary files and directories
    Move-Item "$outPath\sslmap-master\*" $outPath -Force
    Remove-Item "$outPath\sslmap-master" 
    Remove-Item $zipPath -ErrorAction SilentlyContinue
}
catch {
    HandleError((Get-Error).Exception.Message)
}

# Add SSLMap parent path if missing
$varTarget = [EnvironmentVariableTarget]::User
$newPath = [Environment]::GetEnvironmentVariable("PATH", $varTarget)

# Add to environment path if not found
if (-not $newPath.Contains($outPath)) {
    Write-Host "[*] Adding SSLMap location to environment path..."

    if ($newPath[-1] -ne ";") {
        $newPath += ";"
    }
    $newPath += $outPath
    [Environment]::SetEnvironmentVariable("PATH", $newPath, $varTarget)
}

Write-Output "[*] Installation completed successfully!`n"
