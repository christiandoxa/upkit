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
$staged = $null
$backup = $null
try {
    New-Item -ItemType Directory -Path $temp | Out-Null
    Download-Asset 'SHA256SUMS' (Join-Path $temp 'SHA256SUMS')
    $download = Join-Path $temp $asset
    Download-Asset $asset $download
    $pattern = '^([0-9a-fA-F]{64})\s+' + [regex]::Escape($asset) + '$'
    $digests = @(Get-Content -LiteralPath (Join-Path $temp 'SHA256SUMS') | ForEach-Object {
        if ($_ -cmatch $pattern) { $Matches[1].ToLowerInvariant() }
    })
    if ($digests.Count -ne 1) { throw "Missing or invalid SHA256SUMS entry for $asset" }
    if ((Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant() -cne $digests[0]) {
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
    Copy-Item -LiteralPath $download -Destination $staged
    if (Test-Path -LiteralPath $destination) {
        $backup = Join-Path $InstallDir 'upkit.old.exe'
        if (Test-Path -LiteralPath $backup) { Remove-Item -LiteralPath $backup -Force }
        Move-Item -LiteralPath $destination -Destination $backup
    }
    try {
        Move-Item -LiteralPath $staged -Destination $destination
        $staged = $null
    } catch {
        if ($backup) { Move-Item -LiteralPath $backup -Destination $destination }
        throw
    }
    # shortcut: a running Windows binary can retain upkit.old.exe until the next update; use deferred deletion if needed.
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
    if ($staged -and (Test-Path -LiteralPath $staged)) { Remove-Item -LiteralPath $staged -Force }
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
