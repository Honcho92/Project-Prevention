# setup_scheduler.ps1
# One-time setup: creates two Windows scheduled tasks for Scam-Shield.
#   1. "ScamShield Agent"   — every 5 minutes, process unprocessed reports
#   2. "ScamShield Digest"  — Sunday 8pm, send weekly digest DM
#
# Run from an *elevated* PowerShell (right-click → "Run as administrator")
# OR from a non-elevated shell with -NoElevation switch.
#
# After running, both tasks will appear in Task Scheduler. You can start,
# stop, or delete them from there.

param(
    [switch]$NoElevation = $false,
    [int]$AgentIntervalMinutes = 5,
    [string]$DigestDayOfWeek = "Sunday",
    [string]$DigestTime = "20:00"
)

$ErrorActionPreference = "Stop"

# ---- locate the project and the venv python ----
$ProjectDir = "C:\Users\folle\scam-shield"
$PythonExe  = "C:\Users\folle\AppData\Local\hermes\hermes-agent\venv\Scripts\python.exe"

if (-not (Test-Path $ProjectDir)) {
    Write-Error "Project not found at $ProjectDir"
    exit 1
}
if (-not (Test-Path $PythonExe)) {
    Write-Error "Python 3.11 not found at $PythonExe"
    exit 1
}

# ---- check elevation (Task Scheduler needs it for some setups) ----
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin -and -not $NoElevation) {
    Write-Warning "Not running as administrator. Scheduled tasks may fail to create."
    Write-Warning "Re-run with -NoElevation to try anyway, or right-click → Run as administrator."
}

# ---- Agent loop: every N minutes ----
Write-Host ""
Write-Host "=== Setting up 'ScamShield Agent' (every $AgentIntervalMinutes minutes) ==="

$agentAction = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "-m scam_shield.agent_loop" `
    -WorkingDirectory $ProjectDir

$agentTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes $AgentIntervalMinutes) `
    -RepetitionDuration (New-TimeSpan -Days 3650)

# remove old if exists, then create
Unregister-ScheduledTask -TaskName "ScamShield Agent" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "ScamShield Agent" `
    -Action $agentAction -Trigger $agentTrigger `
    -User $env:USERNAME -RunLevel Highest `
    -Description "Processes unprocessed Scam-Shield reports every $AgentIntervalMinutes minutes."
Write-Host "  -> 'ScamShield Agent' registered."

# ---- Weekly digest: Sunday at $DigestTime ----
Write-Host ""
Write-Host "=== Setting up 'ScamShield Digest' ($DigestDayOfWeek at $DigestTime) ==="

$digestAction = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "-m scam_shield.digest --send" `
    -WorkingDirectory $ProjectDir

$digestTrigger = New-ScheduledTaskTrigger -Weekly `
    -DaysOfWeek $DigestDayOfWeek `
    -At $DigestTime

Unregister-ScheduledTask -TaskName "ScamShield Digest" -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask -TaskName "ScamShield Digest" `
    -Action $digestAction -Trigger $digestTrigger `
    -User $env:USERNAME -RunLevel Highest `
    -Description "Sends a weekly Scam-Shield activity digest via Telegram."
Write-Host "  -> 'ScamShield Digest' registered."

Write-Host ""
Write-Host "Done. Tasks will fire even if you're not logged in (since you used -RunLevel Highest)."
Write-Host ""
Write-Host "To run them RIGHT NOW for testing:"
Write-Host "  Start-ScheduledTask -TaskName 'ScamShield Agent'"
Write-Host "  Start-ScheduledTask -TaskName 'ScamShield Digest'"
Write-Host ""
Write-Host "To view / delete them:"
Write-Host "  taskschd.msc"
