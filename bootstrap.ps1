param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

$ErrorActionPreference = "SilentlyContinue"

# ---------------------------
# Self-Elevation Check
# ---------------------------
function Is-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (-not (Is-Admin)) {
    # Rebuild argument string for elevation
    $ArgsString = $ScriptArgs -join " "
    $ElevateArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $ArgsString"
    
    Write-Host "Elevating to Administrator..." -ForegroundColor Yellow
    Start-Process powershell.exe -WindowStyle Hidden -ArgumentList $ElevateArgs -Verb RunAs
    exit
}

# ---------------------------
# Settings
# ---------------------------
$MainScriptURL = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/Configure-WinRMForAnsible.ps1"
$LocalScript   = "$env:ProgramData\Configure-WinRMForAnsible.ps1"
$TaskName      = "ConfigureWinRMStartup"

# Convert array to flat argument string
$ArgsString = $ScriptArgs -join " "

Write-Host "Downloading main script..." -ForegroundColor Gray
try {
    Invoke-WebRequest -Uri $MainScriptURL -OutFile $LocalScript -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Host "Failed to download script: $_" -ForegroundColor Red
    exit 1
}

# ---------------------------
# 1. Run immediately
# ---------------------------
Write-Host "Running main script once..." -ForegroundColor Gray
Start-Process powershell.exe -WindowStyle Hidden `
    -ArgumentList "-ExecutionPolicy Bypass -File `"$LocalScript`" $ArgsString" `
    -Wait

# ---------------------------
# 2. Register Scheduled Task
# ---------------------------

# Task action: download fresh version + execute with same args
$ActionCmd = "Invoke-WebRequest '$MainScriptURL' -OutFile '$LocalScript' -UseBasicParsing; powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File '$LocalScript' $ArgsString"

$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `"$ActionCmd`""

$Trigger = New-ScheduledTaskTrigger -AtStartup

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Write-Host "Creating scheduled task '$TaskName'..." -ForegroundColor Gray
try {
    Register-ScheduledTask -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Principal $Principal `
        -Force `
        -ErrorAction Stop | Out-Null
    
    Write-Host "Bootstrap complete." -ForegroundColor Green
} catch {
    Write-Host "Failed to register scheduled task: $_" -ForegroundColor Red
    exit 1
}