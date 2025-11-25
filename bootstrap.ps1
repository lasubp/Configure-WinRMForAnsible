param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

# ---------------------------
# Settings
# ---------------------------
$MainScriptURL = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/Configure-WinRMForAnsible.ps1"
$LocalScript   = "$env:ProgramData\Configure-WinRMForAnsible.ps1"
$TaskName      = "ConfigureWinRMStartup"

# Convert array to flat argument string
$ArgsString = $ScriptArgs -join " "

Write-Host "Downloading main script..." -ForegroundColor Gray
Invoke-WebRequest -Uri $MainScriptURL -OutFile $LocalScript -UseBasicParsing

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
$ActionCmd = @"
Invoke-WebRequest '$MainScriptURL' -OutFile '$LocalScript' -UseBasicParsing;
powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File '$LocalScript' $ArgsString
"@

$Action = New-ScheduledTaskAction -Execute "powershell.exe" `
    -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -Command `$`"$ActionCmd`$`""

$Trigger = New-ScheduledTaskTrigger -AtStartup

Write-Host "Creating scheduled task '$TaskName'..." -ForegroundColor Gray
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -RunLevel Highest -Force

Write-Host "Bootstrap complete." -ForegroundColor Green
