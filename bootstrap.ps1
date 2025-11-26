param(
    [switch]$UseHTTPS,
    [string]$TrustedHosts
)

# ---------------------------
# URLs and paths
# ---------------------------
$MainURL        = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/Configure-WinRMForAnsible.ps1"
$BootstrapURL   = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/bootstrap.ps1"

$LocalDir       = "$env:ProgramData\WinRMForAnsible"
$LocalBootstrap = "$LocalDir\bootstrap.ps1"
$LocalMain      = "$LocalDir\Configure-WinRMForAnsible.ps1"

$StartupDir     = [Environment]::GetFolderPath("Startup")
$Launcher       = Join-Path $StartupDir "winrm-bootstrap-launch.cmd"
$Task           = "WinRM-SelfHeal"

# Ensure all dirs exist
if (-not (Test-Path $LocalDir)) {
    New-Item -ItemType Directory -Path $LocalDir -Force | Out-Null
}

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

# Proper argument forwarding (PS5.1 compatible)
$ForwardArgs = ""
foreach ($a in $MyInvocation.UnboundArguments) {
    $escaped = $a.Replace('"', '\"')
    $ForwardArgs += '"' + $escaped + '" '
}
$ForwardArgs = $ForwardArgs.Trim()

# ---------------------------
# First-run: ensure local bootstrap exists
# ---------------------------
if (-not (Test-Path $LocalBootstrap)) {
    Invoke-WebRequest -Uri $BootstrapURL -OutFile $LocalBootstrap -UseBasicParsing -ErrorAction Stop
}

# ---------------------------
# SYSTEM → run main script
# ---------------------------
if (Test-IsSystem) {
    Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop
    powershell.exe -ExecutionPolicy Bypass -File $LocalMain $ForwardArgs
    exit
}

# ---------------------------
# NON-ADMIN → create launcher + trigger UAC
# ---------------------------
if (-not (Test-IsAdmin)) {

    # Write launcher
    $cmd = @"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$LocalBootstrap`" $ForwardArgs
"@
    Set-Content -Path $Launcher -Value $cmd -Encoding ASCII

    # UAC prompt
    Start-Process powershell.exe -Verb RunAs `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$LocalBootstrap`" $ForwardArgs" `
        -WindowStyle Hidden

    exit
}

# ---------------------------
# ADMIN → install SYSTEM task running MAIN script
# ---------------------------
if (Test-IsAdmin) {

    # Remove launcher (user approved UAC)
    Remove-Item $Launcher -Force -ErrorAction SilentlyContinue

    # Pull latest main script
    Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop

    # Scheduled task → runs MAIN script, not bootstrap
    $A = New-ScheduledTaskAction -Execute "powershell.exe" `
         -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalMain`" $ForwardArgs"

    $T = New-ScheduledTaskTrigger -AtStartup

    Register-ScheduledTask -TaskName $Task `
                           -Action $A `
                           -Trigger $T `
                           -RunLevel Highest `
                           -Force

    Start-ScheduledTask -TaskName $Task

    exit
}
