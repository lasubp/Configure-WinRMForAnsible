# -----------------------------------------
# CONFIGURATION
# -----------------------------------------
$MainURL        = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/Configure-WinRMForAnsible.ps1"
$WorkDir        = "$env:ProgramData\Configure-WinRM"
$LocalMain      = "$WorkDir\Configure-WinRMForAnsible.ps1"
$LocalBootstrap = "$WorkDir\bootstrap.ps1"
$Launcher       = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\bootstrap-launch.cmd"
$TaskName       = "WinRM-SelfHeal"
$LogRoot        = (Join-Path $env:PUBLIC 'Documents\Configure-WinRMForAnsible')
$LogPath        = "$LogRoot\bootstrap.log"
$script:LogEnabled = $false

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

function Initialize-BootstrapLog {
    try {
        if (-not (Test-Path $LogRoot)) {
            New-Item -ItemType Directory -Path $LogRoot -Force | Out-Null
        }
        $script:LogEnabled = $true
    }
    catch {
        $script:LogEnabled = $false
    }
}

function Write-BootstrapLog {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Info','Warn','Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    if (-not $script:LogEnabled) { return }

    $timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffK")
    $line = "$timestamp [$Level] $Message"

    try {
        Add-Content -Path $LogPath -Value $line -Encoding Ascii -ErrorAction Stop
    }
    catch {
        $script:LogEnabled = $false
    }
}

function Sanitize-Args {
    param([string]$ArgsText)

    if (-not $ArgsText) { return $ArgsText }
    $sanitized = $ArgsText -replace '(?i)(-ServiceUserPass\s+)(\"[^\"]*\"|\S+)', '${1}"***"'
    return $sanitized
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

$script:IsSystem = Test-IsSystem
$script:IsAdmin = Test-IsAdmin
Initialize-BootstrapLog

$safeArgs = Sanitize-Args -ArgsText $ForwardArgs
Write-BootstrapLog -Level Info -Message "Bootstrap start. User=$env:USERNAME IsAdmin=$script:IsAdmin IsSystem=$script:IsSystem"
if ($safeArgs) {
    Write-BootstrapLog -Level Info -Message "Args: $safeArgs"
}

# -----------------------------------------
# SYSTEM → RUN MAIN SCRIPT
# -----------------------------------------
if ($script:IsSystem) {
    try {
        Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop
        Write-BootstrapLog -Level Info -Message "Downloaded main script to '$LocalMain'"
        powershell.exe -NoProfile -ExecutionPolicy Bypass `
            -File $LocalMain $ForwardArgs
        Write-BootstrapLog -Level Info -Message "Main script executed."
    } catch {
        Write-BootstrapLog -Level Error -Message "SYSTEM run failed: $($_.Exception.Message)"
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
    Write-BootstrapLog -Level Info -Message "Created launcher at '$Launcher'"

    # Try invoking UAC — hide "cancelled by user" errors
    try {
        Start-Process powershell.exe -Verb RunAs `
            -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$LocalBootstrap`" $ForwardArgs" `
            -WindowStyle Hidden -ErrorAction Stop
        Write-BootstrapLog -Level Info -Message "UAC prompt accepted."
    } catch {
        Write-BootstrapLog -Level Warn -Message "UAC prompt denied or failed."
        # User declined UAC — intentionally silent
    }

    exit
}

# -----------------------------------------
# ADMIN → SET UP SYSTEM SELF-HEAL TASK
# -----------------------------------------
if ($script:IsAdmin) {

    # Remove launcher (UAC approved)
    Remove-Item $Launcher -Force -ErrorAction SilentlyContinue
    Write-BootstrapLog -Level Info -Message "Removed launcher at '$Launcher'"

    # Download main script fresh
    Invoke-WebRequest -Uri $MainURL -OutFile $LocalMain -UseBasicParsing -ErrorAction Stop
    Write-BootstrapLog -Level Info -Message "Downloaded main script to '$LocalMain'"

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
    Write-BootstrapLog -Level Info -Message "Scheduled task '$TaskName' created."

    # Run once immediately
    Start-ScheduledTask -TaskName $TaskName
    Write-BootstrapLog -Level Info -Message "Scheduled task '$TaskName' started."

    exit
}
