<#
.SYNOPSIS
    Configures Windows Task Scheduler to run `p0 logout` and `gcloud auth revoke`
    for any user when their RDP session is disconnected or they log out.

.DESCRIPTION
    The task runs as SYSTEM so it can start even when the triggering user's session
    is closing. It reads the signing-out user's identity from the event data and sets
    their profile paths as environment variables before invoking the CLI tools.

.PARAMETER Uninstall
    Removes the scheduled task.

.EXAMPLE
    .\Register-P0RdpLogout.ps1

    .\Register-P0RdpLogout.ps1 -Uninstall
#>

param(
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator."
}

$taskName = "P0-RDP-Logout"
$taskPath = "\"

# ---------------------------------------------------------------------------
# Uninstall
# ---------------------------------------------------------------------------
if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Confirm:$false
        Write-Host "Task '$taskName' removed." -ForegroundColor Green
    } else {
        Write-Host "Task '$taskName' not found; nothing to remove." -ForegroundColor Yellow
    }
    return
}

# ---------------------------------------------------------------------------
# Script block run as SYSTEM at disconnect/logoff time.
#
# Because the user's session may already be closing when this runs, the task
# runs as SYSTEM rather than as the user. We identify the signing-out user
# from the most recent logoff/disconnect event, resolve their profile path from
# the registry, and set the relevant environment variables so that p0 and
# gcloud operate against that user's credential store.
#
# Each command is wrapped in try/catch so failures do not block subsequent ones.
# ---------------------------------------------------------------------------
$scriptBlock = @'
$ErrorActionPreference = "Continue"
$log = "$env:SystemRoot\Temp\P0-RDP-Logout.log"
function Log($msg) { "$(Get-Date -Format 'u') $msg" | Out-File $log -Append }

Log "Task started"

# Identify the user from the most recent logoff (23) or disconnect (24) event.
$event = Get-WinEvent `
    -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" `
    -MaxEvents 10 -ErrorAction SilentlyContinue |
    Where-Object { $_.Id -in 23, 24 } |
    Select-Object -First 1

if (-not $event) { Log "No logoff/disconnect event found; exiting"; exit 0 }

$xml      = [xml]$event.ToXml()
$rawUser  = $xml.Event.UserData.EventXML.User  # e.g. "SERVER\alice"
$username = $rawUser -replace '^.*\\', ''       # strip domain/machine prefix
Log "Resolved username: '$username' (raw: '$rawUser')"

if (-not $username) { Log "Empty username; exiting"; exit 0 }

# Resolve the user's profile path from the registry (reliable even after logoff).
$profilePath = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" |
    ForEach-Object { Get-ItemProperty $_.PSPath } |
    Where-Object { (Split-Path $_.ProfileImagePath -Leaf) -eq $username } |
    Select-Object -First 1 -ExpandProperty ProfileImagePath
Log "Profile path: '$profilePath'"

if (-not $profilePath) { Log "Profile path not found; exiting"; exit 0 }

# Set profile-based environment variables so CLI tools find their config files.
$env:USERPROFILE  = $profilePath
$env:APPDATA      = Join-Path $profilePath "AppData\Roaming"
$env:LOCALAPPDATA = Join-Path $profilePath "AppData\Local"
$env:HOME         = $profilePath

# Add common per-user tool install locations to PATH.
$env:PATH = @(
    $env:PATH
    Join-Path $env:LOCALAPPDATA "Google\Cloud SDK\google-cloud-sdk\bin"
    Join-Path $env:LOCALAPPDATA "p0security\bin"
) -join ";"
Log "PATH: $env:PATH"

Log "Running: p0 logout"
try { $out = & p0 logout 2>&1; Log "p0 logout: $out" } catch { Log "p0 logout exception: $_" }

Log "Running: gcloud auth revoke"
try { $out = & gcloud auth revoke --all --verbosity debug 2>&1; Log "gcloud revoke: $out" } catch { Log "gcloud revoke exception: $_" }

Log "Task complete"
'@

$encodedCommand = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($scriptBlock)
)

# ---------------------------------------------------------------------------
# Task action
# ---------------------------------------------------------------------------
$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NonInteractive -WindowStyle Hidden -EncodedCommand $encodedCommand"

# ---------------------------------------------------------------------------
# Trigger: TerminalServices-LocalSessionManager/Operational events:
#   ID 23 - session logoff
#   ID 24 - session disconnected
# ---------------------------------------------------------------------------
$triggerXml = @'
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational">
    <Select Path="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational">
      *[System[EventID=23 or EventID=24]]
    </Select>
  </Query>
</QueryList>
'@

$cimTrigger = Get-CimClass -ClassName MSFT_TaskEventTrigger -Namespace Root/Microsoft/Windows/TaskScheduler
$eventTrigger = New-CimInstance -CimClass $cimTrigger -ClientOnly -Property @{
    Enabled      = $true
    Subscription = $triggerXml
}

# ---------------------------------------------------------------------------
# Principal: SYSTEM, so the task can start even as the user's session closes
# ---------------------------------------------------------------------------
$principal = New-ScheduledTaskPrincipal `
    -UserId    "NT AUTHORITY\SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel  Highest

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances Parallel `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
    -StartWhenAvailable

# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------
$task = New-ScheduledTask `
    -Action    $action `
    -Principal $principal `
    -Settings  $settings `
    -Trigger   $eventTrigger

Register-ScheduledTask `
    -TaskName    $taskName `
    -TaskPath    $taskPath `
    -InputObject $task `
    -Force | Out-Null

Write-Host "Task '$taskName' registered. p0 logout and gcloud auth revoke will run on RDP disconnect or user logout." -ForegroundColor Green
