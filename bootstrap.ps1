param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

# -------------------------
# Settings (you provided URL)
# -------------------------
$MainScriptURL   = "https://raw.githubusercontent.com/lasubp/Configure-WinRMForAnsible/refs/heads/dev/Configure-WinRMForAnsible.ps1"
$InstallDir      = "C:\ProgramData\WinRM-Setup"
$LocalScriptPath = Join-Path $InstallDir "Configure-WinRMForAnsible.ps1"
$TaskName        = "ConfigureWinRM_Startup"
$StartupLauncher = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\Startup\WinRM-Elevate-Launcher.ps1"

# ---- Helper: join and quote args properly ----
function Convert-ArgsToString([string[]]$arr) {
    if (-not $arr) { return "" }
    $out = $arr | ForEach-Object {
        if ($_ -match '\s') { '"{0}"' -f $_ } else { $_ }
    }
    return ($out -join ' ')
}
$ArgsString = Convert-ArgsToString $ScriptArgs

# ---- Admin check ----
$IsAdmin = (
    New-Object Security.Principal.WindowsPrincipal(
        [Security.Principal.WindowsIdentity]::GetCurrent()
    )
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    # Try immediate UAC elevation first
    try {
        $thisPath = $MyInvocation.MyCommand.Definition
        $elevArgs = "-ExecutionPolicy Bypass -NoProfile -File `"$thisPath`" $ArgsString"

        # Start elevated process (this will show UAC)
        Start-Process -FilePath "powershell.exe" -ArgumentList $elevArgs -Verb RunAs -WindowStyle Hidden -ErrorAction Stop
        Write-Output "Requested elevation via UAC. If user accepted, elevated instance will continue."
        # If elevation started, exit this non-elevated process.
        exit 0
    } catch {
        # If immediate elevation failed (user cancelled or can't create elevated process),
        # create a Startup launcher so the next login will show the UAC prompt.
        Write-Warning "Immediate elevation did not start (user cancelled or blocked). Creating Startup launcher to retry on next login."
        $launcherArgs = $ArgsString
        $launcherScript = @"
Start-Process -FilePath 'powershell.exe' -ArgumentList '-ExecutionPolicy Bypass -NoProfile -File `"$thisPath`" $launcherArgs' -Verb RunAs -WindowStyle Hidden
"@

        try {
            New-Item -ItemType Directory -Path (Split-Path $StartupLauncher) -Force | Out-Null
            Set-Content -Path $StartupLauncher -Value $launcherScript -Encoding UTF8
            Write-Output "Startup launcher created: $StartupLauncher"
            Write-Output "It will trigger UAC at next user login. Ask the user to log off/log on or reboot if you want the elevated run now."
        } catch {
            Write-Warning "Failed to create startup launcher: $_"
        }
        exit 0
    }
}

# -------------------------
# Elevated section (runs as Admin or SYSTEM)
# -------------------------

# If previously created, remove Startup launcher (we are elevated now)
if (Test-Path $StartupLauncher) {
    try { Remove-Item -Path $StartupLauncher -Force -ErrorAction SilentlyContinue } catch {}
}

# Ensure install folder exists
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

# Download main script (overwrite)
try {
    Invoke-WebRequest -Uri $MainScriptURL -OutFile $LocalScriptPath -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Error "Failed to download Configure-WinRMForAnsible script from $MainScriptURL`nError: $_"
    exit 1
}

# Create SYSTEM scheduled task that downloads latest script on boot and runs it with same args
try {
    # build the command executed by the scheduled task (careful with quoting)
    $innerCommand = "Invoke-WebRequest -Uri '$MainScriptURL' -OutFile '$LocalScriptPath' -UseBasicParsing; & '$LocalScriptPath' $ArgsString"
    # we wrap innerCommand in & { ... } to run multiple statements
    $taskArgument = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& { $innerCommand }`""

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgument
    $trigger = New-ScheduledTaskTrigger -AtStartup

    # Principal: SYSTEM with highest runlevel
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Register the task (force overwrite if exists)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force

} catch {
    Write-Error "Failed to create SYSTEM scheduled task '$TaskName'. Error: $_"
    # continue — we still try to run the script once now
}

# Run the main script once immediately (elevated)
try {
    Write-Output "Executing main script now with arguments: $ArgsString"
    & powershell.exe -ExecutionPolicy Bypass -NoProfile -File $LocalScriptPath $ScriptArgs
} catch {
    Write-Warning "Running main script failed: $_"
}

Write-Output "Bootstrap finished (elevated). Scheduled TASK: $TaskName (runs at startup as SYSTEM)."
exit 0
