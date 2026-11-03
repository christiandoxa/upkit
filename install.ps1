[CmdletBinding()]
param(
    [string]$Release = $env:UPKIT_RELEASE,
    [string]$InstallDir = $env:UPKIT_INSTALL_DIR
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

if ([string]::IsNullOrWhiteSpace($Release)) { $Release = 'latest' }
if ($Release -cne 'latest') {
    if ($Release -cnotmatch '^v?[0-9]+\.[0-9]+\.[0-9]+$') { throw "Invalid release: $Release" }
    if (-not $Release.StartsWith('v')) { $Release = "v$Release" }
}
if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $InstallDir = Join-Path $env:LOCALAPPDATA 'upkit\bin'
}
$InstallDir = [System.IO.Path]::GetFullPath($InstallDir)
$architecture = $env:PROCESSOR_ARCHITEW6432
if ([string]::IsNullOrWhiteSpace($architecture)) { $architecture = $env:PROCESSOR_ARCHITECTURE }
try {
    $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
} catch {
    # Windows PowerShell may not load RuntimeInformation; use the OS architecture environment.
}
switch ($architecture) {
    { $_ -in 'X64', 'AMD64' } { $target = 'x86_64-pc-windows-msvc' }
    'Arm64' { $target = 'aarch64-pc-windows-msvc' }
    default { throw "Unsupported Windows architecture: $architecture" }
}
$asset = "upkit-$target.exe"
$baseUrl = $env:UPKIT_RELEASE_BASE_URL
if ([string]::IsNullOrWhiteSpace($baseUrl)) {
    if ($Release -ceq 'latest') {
        $baseUrl = 'https://github.com/christiandoxa/upkit/releases/latest/download'
    } else {
        $baseUrl = "https://github.com/christiandoxa/upkit/releases/download/$Release"
    }
}

function Download-Asset([string]$Name, [string]$Destination) {
    if (Test-Path -LiteralPath $baseUrl -PathType Container) {
        Copy-Item -LiteralPath (Join-Path $baseUrl $Name) -Destination $Destination
    } else {
        Invoke-WebRequest -UseBasicParsing -Uri "$($baseUrl.TrimEnd('/'))/$Name" -OutFile $Destination
    }
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
$tempCreated = $false
$ownedTempFiles = [System.Collections.Generic.List[string]]::new()
$staged = $null
$stagedCreated = $false
$backup = $null
try {
    New-Item -ItemType Directory -Path $temp | Out-Null
    $tempCreated = $true
    $checksums = Join-Path $temp 'SHA256SUMS'
    $ownedTempFiles.Add($checksums)
    Download-Asset 'SHA256SUMS' $checksums
    $download = Join-Path $temp $asset
    $ownedTempFiles.Add($download)
    Download-Asset $asset $download
    $digests = @()
    $invalidEntry = $false
    foreach ($line in Get-Content -LiteralPath $checksums) {
        $fields = @($line.Trim() -split '\s+')
        if ($fields.Count -ge 2 -and ($fields[1] -creplace '^\*', '') -ceq $asset) {
            if ($fields.Count -ne 2 -or $fields[0] -cnotmatch '^[0-9a-fA-F]{64}$') {
                $invalidEntry = $true
            }
            $digests += $fields[0].ToLowerInvariant()
        }
    }
    if ($invalidEntry -or $digests.Count -ne 1) { throw "Missing or invalid SHA256SUMS entry for $asset" }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $actualDigest = [BitConverter]::ToString($sha256.ComputeHash([System.IO.File]::ReadAllBytes($download))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
    if ($actualDigest -cne $digests[0]) {
        throw "SHA256 mismatch for $asset"
    }
    $version = (& $download --version | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $version -cnotmatch '^upkit [0-9]+\.[0-9]+\.[0-9]+$') {
        throw 'Downloaded binary did not report a valid upkit version'
    }
    if ($Release -cne 'latest' -and $version -cne "upkit $($Release.TrimStart('v'))") {
        throw "Downloaded version $version does not match $Release"
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $destination = Join-Path $InstallDir 'upkit.exe'
    $staged = Join-Path $InstallDir ('.upkit-' + [guid]::NewGuid().ToString() + '.exe')
    $inputStream = [System.IO.File]::OpenRead($download)
    try {
        $output = [System.IO.File]::Open($staged, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $stagedCreated = $true
        try { $inputStream.CopyTo($output) } finally { $output.Dispose() }
    } finally { $inputStream.Dispose() }

    $destinationItem = Get-Item -Force -LiteralPath $destination -ErrorAction SilentlyContinue
    if ($destinationItem -and $destinationItem.PSIsContainer) {
        throw 'Refusing to replace a directory named upkit.exe'
    }
    if ($destinationItem -and ($destinationItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw 'Refusing to replace a reparse point named upkit.exe'
    }
    if ($destinationItem) {
        $backup = Join-Path $InstallDir ('.upkit-old-' + [guid]::NewGuid().ToString() + '.exe')
        [System.IO.File]::Move($destination, $backup)
    }
    try {
        $stagedItem = Get-Item -Force -LiteralPath $staged -ErrorAction Stop
        if ($stagedItem.PSIsContainer -or ($stagedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw 'Staged executable changed into a reparse point'
        }
        [System.IO.File]::Move($staged, $destination)
        $staged = $null
        $stagedCreated = $false
    } catch {
        $installError = $_
        if ($backup) {
            try {
                [System.IO.File]::Move($backup, $destination)
                $backup = $null
            } catch {
                throw "Install failed and the previous binary remains at '$backup'; the destination changed or cannot be restored: $($_.Exception.Message)"
            }
        }
        throw $installError
    }
    # shortcut: a locked running binary can leave its unique backup; remove it after the process exits.
    if ($backup) { Remove-Item -LiteralPath $backup -Force -ErrorAction SilentlyContinue }

    if ($env:UPKIT_NO_PATH_UPDATE -ne '1') {
        $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
        if (($userPath -split ';') -notcontains $InstallDir) {
            [Environment]::SetEnvironmentVariable('Path', "$InstallDir;$userPath", 'User')
        }
        if (($env:Path -split ';') -notcontains $InstallDir) { $env:Path = "$InstallDir;$env:Path" }
    }
    Write-Host "Installed $version to $destination"
} finally {
    if ($stagedCreated -and (Test-Path -LiteralPath $staged -PathType Leaf)) {
        $stagedItem = Get-Item -Force -LiteralPath $staged -ErrorAction SilentlyContinue
        if ($stagedItem -and -not ($stagedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        }
    }
    if ($tempCreated) {
        foreach ($path in $ownedTempFiles) {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $item = Get-Item -Force -LiteralPath $path -ErrorAction SilentlyContinue
                if ($item -and -not ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
                }
            }
        }
        $tempItem = Get-Item -Force -LiteralPath $temp -ErrorAction SilentlyContinue
        if ($tempItem -and -not ($tempItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        }
    }
}
