param(
    [switch]$UseHTTPS,
    [string]$TrustedHosts
)

# -----------------------------------------
# CONFIGURATION
# -----------------------------------------
$MainURL      = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/Configure-WinRMForAnsible.ps1"
$WorkDir      = "$env:ProgramData\Configure-WinRM"
$LocalMain    = "$WorkDir\Configure-WinRMForAnsible.ps1"
$LocalBootstrap = "$WorkDir\bootstrap.ps1"
$Launcher     = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\bootstrap-launch.cmd"
$TaskName     = "WinRM-SelfHeal"

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
    return ([Environment]::UserName -eq "SYSTEM")
}
function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Forward raw parameters (as typed by user or parent process)
$ForwardArgs = $MyInvocation.UnboundArguments -join ' '

# -----------------------------------------
# SYSTEM → RUN MAIN SCRIPT
# -----------------------------------------
if (Test-IsSystem) {
    try {
        Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop
        powershell.exe -ExecutionPolicy Bypass -File $LocalMain $ForwardArgs
    } catch {
        # SYSTEM should not display errors
    }
    exit
}

# -----------------------------------------
# NON-ADMIN → CREATE RETRY LAUNCHER + REQUEST UAC
# -----------------------------------------
if (-not (Test-IsAdmin)) {

    # Create safe CMD launcher
    $cmd = @"
@echo off
setlocal enableextensions

set PSARGS=$ForwardArgs

powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ^
  "& { & `"$LocalBootstrap`" %PSARGS% }"

endlocal
"@
    Set-Content -Path $Launcher -Value $cmd -Encoding ASCII

    # Try invoking UAC — hide "cancelled by user" errors
    try {
        Start-Sleep -Milliseconds 150
        Start-Process powershell.exe -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$LocalBootstrap`" $ForwardArgs" `
            -WindowStyle Hidden -ErrorAction Stop
    } catch {
        # User declined UAC — no red errors shown
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

    # Scheduled task: SYSTEM context running MAIN SCRIPT
    $A = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalMain`" $ForwardArgs"

    $T = New-ScheduledTaskTrigger -AtStartup

    $P = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" `
        -LogonType ServiceAccount `
        -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName `
                        -Action $A `
                        -Trigger $T `
                        -Principal $P `
                        -Force


    # Run once immediately
    Start-ScheduledTask -TaskName $TaskName

    exit
}
