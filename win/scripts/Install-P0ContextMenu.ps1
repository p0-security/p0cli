<#
.SYNOPSIS
    Installs (or removes) a "Run with P0..." right-click context menu entry.
    The clicked file's path is passed automatically - no manual entry required.

.PARAMETER LauncherPath
    Full path to Start-P0RunAs.ps1 on this machine.
    Defaults to the directory this install script lives in.

.PARAMETER Org
    If supplied, the org is baked in and will not be prompted at runtime.

.PARAMETER Uninstall
    Removes the context menu entry.

.EXAMPLE
    # Install, prompting for org at runtime
    .\Install-P0ContextMenu.ps1

    # Install with a fixed org
    .\Install-P0ContextMenu.ps1 -Org "my-company"

    # Remove
    .\Install-P0ContextMenu.ps1 -Uninstall
#>

param(
    [string]$LauncherPath = (Join-Path $PSScriptRoot "Start-P0RunAs.ps1"),
    [Parameter(Mandatory)][string]$Domain,
    [Parameter(Mandatory)][string]$Org,
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Requires elevation to write to HKCR
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator."
}

$menuName = "RunWithP0"
$menuLabel = "Run with P0..."
$regBase    = "Registry::HKEY_LOCAL_MACHINE\Software\Classes\*\shell\$menuName"
$regBaseNet = "Software\Classes\*\shell\$menuName"

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if ($Uninstall) {
    if (Test-Path -LiteralPath $regBase) {
        Remove-Item -LiteralPath $regBase -Recurse -Force
        Write-Host "Context menu entry removed." -ForegroundColor Green
    } else {
        Write-Host "Context menu entry not found - nothing to remove." -ForegroundColor Yellow
    }
    exit 0
}

# ---------------------------------------------------------------------------
# Validate launcher path
# ---------------------------------------------------------------------------
if (-not (Test-Path $LauncherPath)) {
    throw "Start-P0RunAs.ps1 not found at '$LauncherPath'. Supply -LauncherPath with the correct location."
}

# ---------------------------------------------------------------------------
# Build the registry command.
#
# Using -File instead of -Command means PowerShell receives "%1" as a proper
# named argument, so Windows handles quoting for paths that contain spaces.
# The clicked file's path is passed as -FilePath; no manual entry is needed.
# ---------------------------------------------------------------------------

$fullCommand = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -NoExit -File "{0}" -Org {1} -Domain {2} -Command "%1"' -f $LauncherPath, $Org, $Domain

# ---------------------------------------------------------------------------
# Write registry keys
#
# The path contains a literal '*' (the "all file types" handler key), which
# PowerShell's registry provider treats as a wildcard. Use the .NET
# Microsoft.Win32.Registry API directly to avoid wildcard expansion entirely.
# ---------------------------------------------------------------------------
$iconPath = Join-Path (Split-Path $LauncherPath) "p0.ico"

$hklm = [Microsoft.Win32.Registry]::LocalMachine
$key  = $hklm.CreateSubKey($regBaseNet, $true)
$key.SetValue("",       $menuLabel)
$key.SetValue("Icon",   $iconPath)
$key.Close()

$cmdKey = $hklm.CreateSubKey("$regBaseNet\command", $true)
$cmdKey.SetValue("", $fullCommand)
$cmdKey.Close()

Write-Host "Context menu entry installed." -ForegroundColor Green
Write-Host "  Label:    $menuLabel"
Write-Host "  Launcher: $LauncherPath"
if ($Org) { Write-Host "  Org:      $Org (fixed)" }
Write-Host ""
Write-Host "Right-click any file in Explorer to use it." -ForegroundColor Cyan
