<#
.SYNOPSIS
  Fully configures a Windows host for Ansible remoting via OpenSSH.

.DESCRIPTION
  - Installs OpenSSH.Server capability if missing
  - Enables and starts sshd service
  - Configures sshd_config for secure, automation-friendly settings
  - Adds firewall rule for SSH
  - Optionally creates a local non-interactive admin service user
  - Optionally provisions authorized_keys for a target user
  - Writes structured logs to file (and optional Event Log) with friendly console output
  - No user interaction required
#>

param(
    [int]$Port = 22,
    [switch]$UsePublicKeyOnly = $false,
    [switch]$AllowPasswordAuth = $true,
    [switch]$AllowSftp = $true,
    [string[]]$AllowUsers,
    [string]$PublicKeyFile,
    [string]$AuthorizedKeysPath,
    [string]$DefaultShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
    [string]$LogPath,
    [ValidateSet('text','json')]
    [string]$LogFormat = 'text',
    [switch]$DisableEventLog,
    [switch]$FriendlyErrors = $true,
    # -------------------------------
    # Service user creation
    # -------------------------------
    [switch]$NewUser,
    [string]$ServiceUserName = "ansible_ssh",
    [string]$ServiceUserPass,
    [string]$ServiceUserPassFile
)

# -------------------------------------------------------------------
# CI-friendly defaults and logging
# -------------------------------------------------------------------
$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'

$script:EventSource = 'Configure-SSHForAnsible'
$script:EventLogEnabled = $false
$script:LogFileEnabled = $false
$script:LogFilePath = $null
$script:LogPath = $LogPath
$script:LogFormat = $LogFormat
$script:DisableEventLog = $DisableEventLog
$script:FriendlyErrors = $FriendlyErrors
$script:ExitCode = 0

# -------------------------------------------------------------------
# Require administrative privileges
# -------------------------------------------------------------------
$script:IsAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Initialize-EventLogSource {
    if ($script:DisableEventLog) { return }
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($script:EventSource)) {
            New-EventLog -LogName Application -Source $script:EventSource
        }
        $script:EventLogEnabled = $true
    }
    catch {
        $script:EventLogEnabled = $false
    }
}

function Initialize-LogRoot {
    if (-not $script:IsAdmin) { return }

    $root = Join-Path $env:ProgramData 'Configure-SSHForAnsible'
    try {
        if (-not (Test-Path $root)) {
            New-Item -ItemType Directory -Path $root -Force | Out-Null
        }

        # Allow standard users to write logs (machine-wide log root).
        & icacls $root /grant "Users:(M)" /t | Out-Null
    }
    catch {
        Write-Warning "Failed to initialize log root '$root': $($_.Exception.Message)"
    }
}

function Initialize-LogFile {
    $resolvedLogPath = if ($script:LogPath) {
        $script:LogPath
    }
    else {
        Join-Path $env:ProgramData 'Configure-SSHForAnsible\Configure-SSHForAnsible.log'
    }

    try {
        if (-not $script:IsAdmin -and -not $script:LogPath) {
            return
        }
        $dir = Split-Path -Parent $resolvedLogPath
        if ($dir -and -not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        if (-not (Test-Path $resolvedLogPath)) {
            New-Item -ItemType File -Path $resolvedLogPath -Force | Out-Null
        }

        $script:LogFileEnabled = $true
        $script:LogFilePath = $resolvedLogPath
    }
    catch {
        Write-Warning "Failed to initialize log file '$resolvedLogPath': $($_.Exception.Message)"
    }
}

function ConvertTo-JsonSafe {
    param([Parameter(Mandatory)][string]$Text)

    $escaped = $Text -replace '\\', '\\\\'
    $escaped = $escaped -replace '"', '\"'
    $escaped = $escaped -replace "`r", '\r'
    $escaped = $escaped -replace "`n", '\n'
    $escaped = $escaped -replace "`t", '\t'
    return $escaped
}

function Format-LogLine {
    param(
        [Parameter(Mandatory)]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffK")

    if ($script:LogFormat -eq 'json') {
        $msg = ConvertTo-JsonSafe -Text $Message
        return "{""ts"":""$timestamp"",""level"":""$Level"",""msg"":""$msg""}"
    }

    return "$timestamp [$Level] $Message"
}

function Write-Log {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Info','Warn','Error')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $formatted = Format-LogLine -Level $Level -Message $Message
    $consoleMessage = $Message
    if ($script:LogFormat -eq 'json') {
        $consoleMessage = $formatted
    }

    switch ($Level) {
        'Info'  { Write-Output $consoleMessage }
        'Warn'  { Write-Warning $consoleMessage }
        'Error' {
            if ($script:FriendlyErrors) {
                Write-Host $consoleMessage -ForegroundColor Red
            }
            else {
                Write-Error $consoleMessage
            }
            $script:ExitCode = 1
        }
    }

    if ($script:LogFileEnabled) {
        try {
            Add-Content -Path $script:LogFilePath -Value $formatted -Encoding Ascii -ErrorAction Stop
        }
        catch {
            $script:LogFileEnabled = $false
            Write-Warning "Log file write failed; disabling file logging: $($_.Exception.Message)"
        }
    }

    if ($script:EventLogEnabled) {
        try {
            $entryType = switch ($Level) {
                'Info'  { 'Information' }
                'Warn'  { 'Warning' }
                'Error' { 'Error' }
            }
            $eventId = switch ($Level) {
                'Info'  { 2000 }
                'Warn'  { 2001 }
                'Error' { 2002 }
            }

            Write-EventLog -LogName Application -Source $script:EventSource -EntryType $entryType -EventId $eventId -Message $Message
        }
        catch {
            # Best-effort logging to event log; do not fail script on log issues.
        }
    }
}

# -------------------------------------------------------------------
# Firewall rule helper
# -------------------------------------------------------------------
function Set-SSHFirewallRule {
    param (
        [Parameter(Mandatory)]
        [int]$Port
    )

    $ruleName = "OpenSSH-SSH-$Port"
    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue

    if ($existingRule) {
        Write-Log -Level Info -Message "Firewall rule '$ruleName' already exists. Ensuring correct settings..."
        $existingRule |
            Set-NetFirewallRule -Profile Domain,Private,Public -Direction Inbound -Action Allow |
            Out-Null

        Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existingRule |
            Set-NetFirewallPortFilter -LocalPort $Port -Protocol TCP |
            Out-Null
    }
    else {
        Write-Log -Level Info -Message "Creating firewall rule '$ruleName'..."
        New-NetFirewallRule `
            -Name $ruleName `
            -DisplayName $ruleName `
            -Description "Allow OpenSSH ($Port) for Ansible" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort $Port `
            -Action Allow `
            -Profile Domain,Private,Public |
            Out-Null
    }
}

function Set-OpenSSHInstalled {
    Write-Log -Level Info -Message "Ensuring OpenSSH.Server is installed..."
    try {
        $cap = Get-WindowsCapability -Online -Name OpenSSH.Server* -ErrorAction Stop | Select-Object -First 1
        if (-not $cap) {
            throw "OpenSSH.Server capability not found"
        }
        if ($cap.State -ne 'Installed') {
            Write-Log -Level Info -Message "Installing OpenSSH.Server capability..."
            Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop | Out-Null
        }
        else {
            Write-Log -Level Info -Message "OpenSSH.Server already installed."
        }
    }
    catch {
        throw "Failed to install OpenSSH.Server: $($_.Exception.Message)"
    }
}

function Set-SSHDService {
    Write-Log -Level Info -Message "Ensuring sshd service is enabled and running..."
    try {
        $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
        if ($svc.StartMode -ne 'Auto') {
            sc.exe config sshd start= auto | Out-Null
        }
        if ($svc.State -ne 'Running') {
            Start-Service sshd -ErrorAction Stop
        }
    }
    catch {
        throw "Failed to configure sshd service: $($_.Exception.Message)"
    }
}

function Set-DefaultShell {
    param([Parameter(Mandatory)][string]$ShellPath)
    try {
        if (-not (Test-Path $ShellPath)) {
            Write-Log -Level Warn -Message "Default shell path not found: $ShellPath"
            return
        }
        $path = 'HKLM:\SOFTWARE\OpenSSH'
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        Set-ItemProperty -Path $path -Name 'DefaultShell' -Value $ShellPath -Type String -Force
    }
    catch {
        Write-Log -Level Warn -Message "Failed to set DefaultShell: $($_.Exception.Message)"
    }
}

function Set-SSHDConfig {
    param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][bool]$PasswordAuth,
        [Parameter(Mandatory)][bool]$PubkeyAuth,
        [Parameter(Mandatory)][bool]$AllowSftp,
        [string[]]$AllowUsers
    )

    if (-not (Test-Path $ConfigPath)) {
        throw "sshd_config not found at $ConfigPath"
    }

    $raw = Get-Content $ConfigPath -Raw
    $lines = $raw -split "`r?`n"

    function Upsert-ConfigLine {
        param(
            [string]$Key,
            [string]$Value
        )

        $pattern = "^(#\s*)?$([regex]::Escape($Key))\b.*$"
        $found = $false
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match $pattern) {
                $lines[$i] = "$Key $Value"
                $found = $true
                break
            }
        }
        if (-not $found) {
            $lines += "$Key $Value"
        }
    }

    Upsert-ConfigLine -Key 'Port' -Value $Port
    Upsert-ConfigLine -Key 'PasswordAuthentication' -Value ($PasswordAuth ? 'yes' : 'no')
    Upsert-ConfigLine -Key 'PubkeyAuthentication' -Value ($PubkeyAuth ? 'yes' : 'no')
    Upsert-ConfigLine -Key 'KbdInteractiveAuthentication' -Value ($PasswordAuth ? 'yes' : 'no')
    Upsert-ConfigLine -Key 'PermitEmptyPasswords' -Value 'no'
    Upsert-ConfigLine -Key 'PermitRootLogin' -Value 'no'
    Upsert-ConfigLine -Key 'GSSAPIAuthentication' -Value 'no'
    Upsert-ConfigLine -Key 'AuthorizedKeysFile' -Value '.ssh/authorized_keys'

    if ($AllowSftp) {
        Upsert-ConfigLine -Key 'Subsystem' -Value 'sftp sftp-server.exe'
    }

    if ($AllowUsers -and $AllowUsers.Count -gt 0) {
        Upsert-ConfigLine -Key 'AllowUsers' -Value ($AllowUsers -join ' ')
    }

    $lines -join "`r`n" | Set-Content -Path $ConfigPath -Encoding Ascii
}

function Set-AuthorizedKeys {
    param(
        [Parameter(Mandatory)][string]$TargetUser,
        [string]$PublicKeyFile,
        [string]$AuthorizedKeysPath
    )

    if (-not $PublicKeyFile) { return }
    if (-not (Test-Path $PublicKeyFile)) {
        throw "Public key file not found: $PublicKeyFile"
    }

    $key = (Get-Content $PublicKeyFile -Raw).Trim()
    if (-not $key) {
        throw "Public key file is empty: $PublicKeyFile"
    }

    $user = Get-LocalUser -Name $TargetUser -ErrorAction Stop
    $sid = $user.SID.Value

    $userProfilePath = (Get-CimInstance Win32_UserProfile | Where-Object { $_.SID -eq $sid }).LocalPath
    if (-not $userProfilePath) {
        $userProfilePath = "C:\Users\$TargetUser"
    }

    $sshDir = Join-Path $userProfilePath '.ssh'
    if (-not (Test-Path $sshDir)) {
        New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    }

    $authKeys = if ($AuthorizedKeysPath) { $AuthorizedKeysPath } else { Join-Path $sshDir 'authorized_keys' }
    if (-not (Test-Path $authKeys)) {
        New-Item -ItemType File -Path $authKeys -Force | Out-Null
    }

    $existing = Get-Content $authKeys -ErrorAction SilentlyContinue
    if ($existing -notcontains $key) {
        Add-Content -Path $authKeys -Value $key -Encoding Ascii
    }

    # Secure permissions: user + SYSTEM + Administrators
    & icacls $authKeys /inheritance:r /grant "$TargetUser:(R)" "SYSTEM:(F)" "Administrators:(F)" | Out-Null
    & icacls $sshDir /inheritance:r /grant "$TargetUser:(F)" "SYSTEM:(F)" "Administrators:(F)" | Out-Null
}

# -------------------------------------------------------------------
# Create non-interactive local service user (optional)
# -------------------------------------------------------------------
function Hide-UserFromLogonUI {
    param(
        [Parameter(Mandatory)]
        [string]$UserName
    )

    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }

    New-ItemProperty -Path $regPath -Name $UserName -PropertyType DWord -Value 0 -Force | Out-Null
}

function New-AnsibleServiceUser {
    param(
        [Parameter(Mandatory)]
        [string]$UserName,

        [string]$PlainPassword,

        [string]$PasswordFile
    )

    Write-Log -Level Info -Message "Ensuring local service user '$UserName' exists..."

    $existing = Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue
    if (-not $existing) {
        $plain = $null

        if ($PasswordFile) {
            if (-not (Test-Path $PasswordFile)) {
                throw "Password file not found: $PasswordFile"
            }
            $plain = (Get-Content $PasswordFile -Raw).Trim()
            Remove-Item $PasswordFile -Force -ErrorAction SilentlyContinue
        }
        elseif ($PlainPassword) {
            Write-Log -Level Warn -Message "ServiceUserPass provided via command line can leak via logs/process args. Prefer -ServiceUserPassFile when possible."
            $plain = $PlainPassword
        }

        if ($plain) {
            $securePassword = ConvertTo-SecureString $plain -AsPlainText -Force
        }
        else {
            Add-Type -AssemblyName System.Web
            $generatedPlain = [System.Web.Security.Membership]::GeneratePassword(32, 6)
            $securePassword = ConvertTo-SecureString $generatedPlain -AsPlainText -Force
        }

        New-LocalUser `
            -Name $UserName `
            -Password $securePassword `
            -Description "Ansible SSH service account" `
            -PasswordNeverExpires `
            -UserMayNotChangePassword | Out-Null

        Write-Log -Level Info -Message "User '$UserName' created."
    }
    else {
        Write-Log -Level Info -Message "User '$UserName' already exists. Applying hardening..."
    }

    Add-LocalGroupMember -Group "Administrators" -Member $UserName -ErrorAction SilentlyContinue
    Enable-LocalUser -Name $UserName -ErrorAction SilentlyContinue

    try {
        $lu = Get-LocalUser -Name $UserName -ErrorAction Stop
        $sidToken = "*$($lu.SID.Value)"
        $tmp = "$env:TEMP\secpol-ansible-ssh.cfg"

        secedit /export /cfg $tmp | Out-Null
        $content = Get-Content $tmp -Encoding Unicode

        if ($content -notmatch '^SeDenyInteractiveLogonRight') {
            $content += "SeDenyInteractiveLogonRight ="
        }
        if ($content -notmatch '^SeDenyRemoteInteractiveLogonRight') {
            $content += "SeDenyRemoteInteractiveLogonRight ="
        }

        $content = $content -replace '^(SeDenyInteractiveLogonRight\s*=\s*)(.*)$', {
            $lhs = $Matches[1]
            $rhs = $Matches[2].Trim()
            $tokens = @()
            if ($rhs) {
                $tokens = $rhs -split "\s*,\s*" | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() }
            }
            $set = @{}
            foreach ($t in $tokens) {
                $nt = $t
                if ($nt -match "^S-1-") { $nt = "*$nt" }
                $set[$nt.ToUpperInvariant()] = $true
            }
            if (-not $set.ContainsKey($sidToken.ToUpperInvariant())) {
                $tokens += $sidToken
            }
            "$lhs" + ($tokens -join ",")
        }

        $content = $content -replace '^(SeDenyRemoteInteractiveLogonRight\s*=\s*)(.*)$', {
            $lhs = $Matches[1]
            $rhs = $Matches[2].Trim()
            $tokens = @()
            if ($rhs) {
                $tokens = $rhs -split "\s*,\s*" | Where-Object { $_ -and $_.Trim() } | ForEach-Object { $_.Trim() }
            }
            $set = @{}
            foreach ($t in $tokens) {
                $nt = $t
                if ($nt -match "^S-1-") { $nt = "*$nt" }
                $set[$nt.ToUpperInvariant()] = $true
            }
            if (-not $set.ContainsKey($sidToken.ToUpperInvariant())) {
                $tokens += $sidToken
            }
            "$lhs" + ($tokens -join ",")
        }

        $content | Set-Content $tmp -Encoding Unicode
        secedit /configure /db secedit.sdb /cfg $tmp /areas USER_RIGHTS | Out-Null
    }
    catch {
        Write-Log -Level Warn -Message "Failed to apply logon restrictions for '$UserName': $($_.Exception.Message)"
    }

    try {
        Hide-UserFromLogonUI -UserName $UserName
    }
    catch {
        Write-Log -Level Warn -Message "Failed to hide '$UserName' from logon UI: $($_.Exception.Message)"
    }

    Write-Log -Level Info -Message "Service user '$UserName' created and hardened."
}

Initialize-EventLogSource
Initialize-LogRoot
Initialize-LogFile

trap {
    Write-Log -Level Error -Message "Unhandled error: $($_.Exception.Message)"
    exit 1
}

if (-not $script:IsAdmin) {
    Write-Log -Level Error -Message "This script must be run as Administrator."
    Write-Log -Level Error -Message "Please re-run it in an elevated PowerShell session."
    exit 1
}

if ($UsePublicKeyOnly) {
    $AllowPasswordAuth = $false
}

if ($NewUser) {
    New-AnsibleServiceUser `
        -UserName $ServiceUserName `
        -PlainPassword $ServiceUserPass `
        -PasswordFile $ServiceUserPassFile
}

Write-Log -Level Info -Message "=== Configuring OpenSSH for Ansible ==="

Set-OpenSSHInstalled
Set-SSHDService
Set-DefaultShell -ShellPath $DefaultShell

$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
Set-SSHDConfig `
    -ConfigPath $sshdConfig `
    -Port $Port `
    -PasswordAuth:$AllowPasswordAuth `
    -PubkeyAuth:$true `
    -AllowSftp:$AllowSftp `
    -AllowUsers $AllowUsers

if ($NewUser -and $PublicKeyFile) {
    Set-AuthorizedKeys -TargetUser $ServiceUserName -PublicKeyFile $PublicKeyFile -AuthorizedKeysPath $AuthorizedKeysPath
}
elseif ($PublicKeyFile -and $AllowUsers -and $AllowUsers.Count -eq 1) {
    Set-AuthorizedKeys -TargetUser $AllowUsers[0] -PublicKeyFile $PublicKeyFile -AuthorizedKeysPath $AuthorizedKeysPath
}

Set-SSHFirewallRule -Port $Port
Restart-Service sshd -Force

Write-Log -Level Info -Message "=== OpenSSH configuration complete ==="
Write-Log -Level Info -Message "Port: $Port"
Write-Log -Level Info -Message "PasswordAuthentication: $AllowPasswordAuth"
Write-Log -Level Info -Message "PubkeyAuthentication: $true"
Write-Log -Level Info -Message "AllowUsers: $(if ($AllowUsers) { $AllowUsers -join ',' } else { '(all)' })"

exit $script:ExitCode
