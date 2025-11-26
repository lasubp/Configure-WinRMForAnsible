param(
    [switch]$UseHTTPS,
    [string]$TrustedHosts
)

# ---------------------------
# URLs and paths
# ---------------------------
$MainURL   = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/Configure-WinRMForAnsible.ps1"
$LocalMain = "$env:ProgramData\Configure-WinRMForAnsible.ps1"
$Launcher  = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\bootstrap-launch.cmd"
$Task      = "WinRM-SelfHeal"

# ---------------------------
# Helper functions
# ---------------------------
function Test-IsSystem {
    return ([Environment]::UserName -eq "SYSTEM")
}
function Test-IsAdmin {
    $p = New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Collect all parameters exactly as user typed
$ForwardArgs = $MyInvocation.UnboundArguments -join ' '

# ---------------------------
# SYSTEM → run MAIN script
# ---------------------------
if (Test-IsSystem) {
    Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop
    powershell.exe -ExecutionPolicy Bypass -File $LocalMain $ForwardArgs
    exit
}

# ---------------------------
# Non-admin → create retry + request UAC
# ---------------------------
if (-not (Test-IsAdmin)) {

    # Auto-retry launcher
    $cmd = @"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" $ForwardArgs
"@
    Set-Content -Path $Launcher -Value $cmd -Encoding ASCII

    # Trigger UAC
    Start-Process powershell.exe -Verb RunAs `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" $ForwardArgs" `
        -WindowStyle Hidden

    exit
}

# ---------------------------
# ADMIN → create SYSTEM task running the MAIN script
# ---------------------------
if (Test-IsAdmin) {

    # Remove launcher after successful UAC
    Remove-Item $Launcher -Force -ErrorAction SilentlyContinue

    # Download main script fresh before installing task
    Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop

    # Scheduled task ACTION → now runs *main script*, not bootstrap
    $A = New-ScheduledTaskAction -Execute "powershell.exe" `
         -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalMain`" $ForwardArgs"

    # Trigger at every boot
    $T = New-ScheduledTaskTrigger -AtStartup

    Register-ScheduledTask -TaskName $Task `
                           -Action $A `
                           -Trigger $T `
                           -RunLevel Highest `
                           -Force

    # Run immediately (SYSTEM context)
    Start-ScheduledTask -TaskName $Task

    exit
}
