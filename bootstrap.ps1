param(
    [switch]$UseHTTPS,
    [string]$TrustedHosts
)

# ---------------------------
# URLs and paths
# ---------------------------
$MainURL   = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/Configure-WinRMForAnsible.ps1"
$BootstrapURL = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/bootstrap.ps1"

$LocalDir  = "$env:ProgramData\WinRMForAnsible"
$LocalBootstrap = "$LocalDir\bootstrap.ps1"
$LocalMain = "$LocalDir\Configure-WinRMForAnsible.ps1"

$StartupDir = [Environment]::GetFolderPath("Startup")
$Launcher  = Join-Path $StartupDir "winrm-bootstrap-launch.cmd"
$Task      = "WinRM-SelfHeal"

# Ensure folder exists
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

# Forward arguments exactly as user typed, quoted safely
$ForwardArgs = $MyInvocation.UnboundArguments |
    ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' } |
    Join-String ' '

# ---------------------------
# Ensure local bootstrap exists (first-run from GitHub)
# ---------------------------
if (-not (Test-Path $LocalBootstrap)) {
    Invoke-WebRequest -Uri $BootstrapURL -OutFile $LocalBootstrap -UseBasicParsing -ErrorAction Stop
}

# ---------------------------
# SYSTEM → run MAIN script
# ---------------------------
if (Test-IsSystem) {
    Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop
    powershell.exe -ExecutionPolicy Bypass -File $LocalMain $ForwardArgs
    exit
}

# ---------------------------
# Non-admin → save launcher + request UAC
# ---------------------------
if (-not (Test-IsAdmin)) {

    # Launcher points to the *local ProgramData bootstrap*
    $cmd = @"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$LocalBootstrap`" $ForwardArgs
"@

    Set-Content -Path $Launcher -Value $cmd -Encoding ASCII

    # Trigger UAC, now pointing to *local copy*
    Start-Process powershell.exe -Verb RunAs `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$LocalBootstrap`" $ForwardArgs" `
        -WindowStyle Hidden

    exit
}

# ---------------------------
# ADMIN → create SYSTEM task running the main script
# ---------------------------
if (Test-IsAdmin) {

    # Remove launcher – UAC succeeded
    Remove-Item $Launcher -Force -ErrorAction SilentlyContinue

    # Download main script fresh
    Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop

    # ACTION → now runs *main script*, not bootstrap
    $A = New-ScheduledTaskAction -Execute "powershell.exe" `
         -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalMain`" $ForwardArgs"

    # Trigger at every boot
    $T = New-ScheduledTaskTrigger -AtStartup

    Register-ScheduledTask -TaskName $Task `
                           -Action $A `
                           -Trigger $T `
                           -RunLevel Highest `
                           -Force

    Start-ScheduledTask -TaskName $Task

    exit
}
