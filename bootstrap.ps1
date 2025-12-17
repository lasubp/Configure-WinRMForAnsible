# -----------------------------------------
# CONFIGURATION
# -----------------------------------------
$MainURL        = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/Configure-WinRMForAnsible.ps1"
$WorkDir        = "$env:ProgramData\Configure-WinRM"
$LocalMain      = "$WorkDir\Configure-WinRMForAnsible.ps1"
$LocalBootstrap = "$WorkDir\bootstrap.ps1"
$Launcher       = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\bootstrap-launch.cmd"
$TaskName       = "WinRM-SelfHeal"

# Ensure working directory exists:
New-Item -ItemType Directory -Path $WorkDir -Force | Out-Null

# Ensure bootstrap lives in permanent location:
if ($MyInvocation.MyCommand.Path -ne $LocalBootstrap) {
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $LocalBootstrap -Force
}

# -----------------------------------------
# HELPERS
# -----------------------------------------
function Test-IsSystem {
    [Environment]::UserName -eq "SYSTEM"
}

function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Raw, tokenized arguments as PowerShell received them
$ForwardArgs = (
    $args | ForEach-Object {
        if ($_ -match '\s') {
            '"' + ($_ -replace '"','`"') + '"'
        } else {
            $_
        }
    }
) -join ' '

# -----------------------------------------
# SYSTEM → RUN MAIN SCRIPT
# -----------------------------------------
if (Test-IsSystem) {
    try {
        Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop
        powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $LocalMain $ForwardArgs
    } catch {
        # SYSTEM should be silent
    }
    exit
}

# -----------------------------------------
# NON-ADMIN → CREATE RETRY LAUNCHER + REQUEST UAC
# -----------------------------------------
if (-not (Test-IsAdmin)) {

    $cmd = @"
@echo off
setlocal

powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden ^
  -File "$LocalBootstrap" $ForwardArgs

endlocal
"@

    Set-Content -Path $Launcher -Value $cmd -Encoding ASCII

    # Try invoking UAC — hide "cancelled by user" errors
    try {
        Start-Process powershell.exe -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$LocalBootstrap`" $ForwardArgs" `
            -WindowStyle Hidden -ErrorAction Stop
    } catch {
        # User declined UAC — intentionally silent
    }

    exit
}

# -----------------------------------------
# ADMIN → SET UP SYSTEM SELF-HEAL TASK
# -----------------------------------------
if (Test-IsAdmin) {

    # Remove launcher (UAC approved)
    Remove-Item $Launcher -Force -ErrorAction SilentlyContinue

    # Download main script fresh
    Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop

    $Action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalMain`" $ForwardArgs"

    $Trigger = New-ScheduledTaskTrigger -AtStartup

    $Principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    Register-ScheduledTask `
        -TaskName $TaskName `
        -Action $Action `
        -Trigger $Trigger `
        -Principal $Principal `
        -Force

    # Run once immediately
    Start-ScheduledTask -TaskName $TaskName

    exit
}
