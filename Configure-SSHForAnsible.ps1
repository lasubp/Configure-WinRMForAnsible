<#
.SYNOPSIS
  Fully configures a Windows host for Ansible remoting via OpenSSH.

.DESCRIPTION
  Design decisions follow official Microsoft OpenSSH-on-Windows and Ansible Windows-over-SSH guidance:
  - Use in-box OpenSSH.Server capability (Windows optional feature)
  - Keep sshd service bound to the in-box binary under %SystemRoot%\System32\OpenSSH
  - Preserve Windows default admin-key behavior (administrators_authorized_keys)
  - Enforce strict ACLs under %ProgramData%\ssh to avoid service startup failures
  - Keep optional local service-user creation and logging behavior
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
    [switch]$NewUser,
    [string]$ServiceUserName = "ansible_ssh",
    [string]$ServiceUserPass,
    [string]$ServiceUserPassFile
)

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
        [Parameter(Mandatory)][string]$Level,
        [Parameter(Mandatory)][string]$Message
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
    $consoleMessage = if ($script:LogFormat -eq 'json') { $formatted } else { $Message }

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
            # Best-effort only
        }
    }
}

function Get-ExitHex {
    param([int]$Code)
    return ('0x{0:X8}' -f ([uint32]$Code))
}

function Get-OpenSSHServerCapability {
    return Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop | Select-Object -First 1
}

function Set-OpenSSHInstalled {
    param([switch]$ForceReinstall)

    Write-Log -Level Info -Message "Ensuring OpenSSH.Server is installed..."
    try {
        $cap = Get-OpenSSHServerCapability
        if (-not $cap) {
            throw "OpenSSH.Server capability not found."
        }

        if ($ForceReinstall -and $cap.State -eq 'Installed') {
            Write-Log -Level Warn -Message "Reinstalling OpenSSH.Server capability..."
            Remove-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop | Out-Null
            $cap = Get-OpenSSHServerCapability
        }

        if ($cap.State -ne 'Installed') {
            Add-WindowsCapability -Online -Name $cap.Name -ErrorAction Stop | Out-Null
            Write-Log -Level Info -Message "OpenSSH.Server installed."
        }
        else {
            Write-Log -Level Info -Message "OpenSSH.Server already installed."
        }
    }
    catch {
        throw "Failed to install OpenSSH.Server: $($_.Exception.Message)"
    }
}

function Get-SSHDExecutablePath {
    $candidates = @(
        (Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'),
        (Join-Path $env:ProgramFiles 'OpenSSH\sshd.exe')
    )
    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }
    return $null
}

function Get-SSHKeygenPath {
    $sshdExe = Get-SSHDExecutablePath
    if (-not $sshdExe) { return $null }
    $candidate = Join-Path (Split-Path -Parent $sshdExe) 'ssh-keygen.exe'
    if (Test-Path $candidate) { return $candidate }
    return $null
}
function Set-SSHDConfigFile {
    param([Parameter(Mandatory)][string]$ConfigPath)

    if (Test-Path $ConfigPath) { return }

    $configDir = Split-Path -Parent $ConfigPath
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    $defaults = @(
        (Join-Path $env:SystemRoot 'System32\OpenSSH\sshd_config_default'),
        (Join-Path $env:SystemRoot 'System32\OpenSSH\sshd_config'),
        (Join-Path $env:ProgramFiles 'OpenSSH\sshd_config_default'),
        (Join-Path $env:ProgramFiles 'OpenSSH\sshd_config')
    )

    foreach ($defaultPath in $defaults) {
        if ($defaultPath -and (Test-Path $defaultPath)) {
            Copy-Item -Path $defaultPath -Destination $ConfigPath -Force
            Write-Log -Level Warn -Message "sshd_config was missing. Restored from '$defaultPath'."
            return
        }
    }

    $minimal = @(
        '# Auto-generated because sshd_config was missing',
        'Port 22',
        'PubkeyAuthentication yes',
        'PasswordAuthentication yes',
        'PermitEmptyPasswords no',
        'AuthorizedKeysFile .ssh/authorized_keys',
        'Subsystem sftp sftp-server.exe'
    )
    $minimal -join "`r`n" | Set-Content -Path $ConfigPath -Encoding Ascii
    Write-Log -Level Warn -Message "sshd_config was missing and no default template was found. Created minimal configuration."
}

function ConvertTo-MutableLineList {
    param([object]$InputLines)

    $mutable = New-Object System.Collections.ArrayList

    if ($null -eq $InputLines) {
        return ,$mutable
    }

    if ($InputLines -is [string]) {
        if (-not [string]::IsNullOrWhiteSpace($InputLines)) {
            [void]$mutable.Add($InputLines)
        }
        return ,$mutable
    }

    if ($InputLines -is [System.Collections.IEnumerable] -and -not ($InputLines -is [System.Collections.IDictionary])) {
        foreach ($item in $InputLines) {
            if ($null -ne $item) {
                [void]$mutable.Add([string]$item)
            }
        }
        return ,$mutable
    }

    [void]$mutable.Add([string]$InputLines)
    return ,$mutable
}

function Set-DirectiveInList {
    param(
        [Parameter(Mandatory)][object]$Lines,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Value
    )

    $Lines = ConvertTo-MutableLineList -InputLines $Lines

    $pattern = "^\s*#?\s*$([regex]::Escape($Key))\b"
    $firstIndex = -1

    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match $pattern) {
            if ($firstIndex -lt 0) {
                $firstIndex = $i
                $Lines[$i] = "$Key $Value"
            }
            else {
                $Lines.RemoveAt($i)
                $i--
            }
        }
    }

    if ($firstIndex -lt 0) {
        [void]$Lines.Add("$Key $Value")
    }

    return ,$Lines
}

function Remove-DirectiveFromList {
    param(
        [Parameter(Mandatory)][object]$Lines,
        [Parameter(Mandatory)][string]$Key
    )

    $Lines = ConvertTo-MutableLineList -InputLines $Lines

    $pattern = "^\s*#?\s*$([regex]::Escape($Key))\b"
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match $pattern) {
            $Lines.RemoveAt($i)
            $i--
        }
    }

    return ,$Lines
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

    Set-SSHDConfigFile -ConfigPath $ConfigPath

    $raw = Get-Content -Path $ConfigPath -Raw -ErrorAction Stop
    $allLines = $raw -split "`r?`n"
    # Recover from older buggy script versions that accidentally wrote non-directive artifacts.
    $allLines = @($allLines | Where-Object {
        $_ -notmatch '^\s*\d+\s*$' -and
        $_ -notmatch '^\s*System\.Collections\.ArrayList\s*$'
    })

    $firstMatchIndex = -1
    for ($i = 0; $i -lt $allLines.Count; $i++) {
        if ($allLines[$i] -match '^\s*Match\s+') {
            $firstMatchIndex = $i
            break
        }
    }

    $topLines = New-Object System.Collections.ArrayList
    $tailLines = New-Object System.Collections.ArrayList

    if ($firstMatchIndex -ge 0) {
        for ($i = 0; $i -lt $firstMatchIndex; $i++) { [void]$topLines.Add($allLines[$i]) }
        for ($i = $firstMatchIndex; $i -lt $allLines.Count; $i++) { [void]$tailLines.Add($allLines[$i]) }
    }
    else {
        foreach ($line in $allLines) { [void]$topLines.Add($line) }
    }

    $password = if ($PasswordAuth) { 'yes' } else { 'no' }
    $pubkey = if ($PubkeyAuth) { 'yes' } else { 'no' }

    $topLines = Set-DirectiveInList -Lines $topLines -Key 'Port' -Value $Port
    $topLines = Set-DirectiveInList -Lines $topLines -Key 'PasswordAuthentication' -Value $password
    $topLines = Set-DirectiveInList -Lines $topLines -Key 'PubkeyAuthentication' -Value $pubkey
    $topLines = Set-DirectiveInList -Lines $topLines -Key 'PermitEmptyPasswords' -Value 'no'
    $topLines = Set-DirectiveInList -Lines $topLines -Key 'AuthorizedKeysFile' -Value '.ssh/authorized_keys'

    if ($AllowSftp) {
        $topLines = Set-DirectiveInList -Lines $topLines -Key 'Subsystem' -Value 'sftp sftp-server.exe'
    }
    else {
        $topLines = Remove-DirectiveFromList -Lines $topLines -Key 'Subsystem'
    }

    if ($AllowUsers -and $AllowUsers.Count -gt 0) {
        $topLines = Set-DirectiveInList -Lines $topLines -Key 'AllowUsers' -Value ($AllowUsers -join ' ')
    }
    else {
        $topLines = Remove-DirectiveFromList -Lines $topLines -Key 'AllowUsers'
    }

    $finalLines = New-Object System.Collections.ArrayList
    foreach ($line in $topLines) { [void]$finalLines.Add($line) }
    foreach ($line in $tailLines) { [void]$finalLines.Add($line) }

    $finalLines -join "`r`n" | Set-Content -Path $ConfigPath -Encoding Ascii
}

function Set-SSHHostKeys {
    Write-Log -Level Info -Message "Ensuring OpenSSH host keys exist..."

    $keyRoot = Join-Path $env:ProgramData 'ssh'
    if (-not (Test-Path $keyRoot)) {
        New-Item -ItemType Directory -Path $keyRoot -Force | Out-Null
    }

    $existing = Get-ChildItem -Path $keyRoot -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue
    if ($existing -and $existing.Count -gt 0) { return }

    $sshKeygen = Get-SSHKeygenPath
    if (-not $sshKeygen) {
        throw "Cannot find ssh-keygen.exe after OpenSSH.Server installation."
    }

    $output = & $sshKeygen -A 2>&1
    if ($LASTEXITCODE -ne 0) {
        $details = (($output | Where-Object { $_ }) -join ' | ')
        if (-not $details) { $details = "ssh-keygen exited with code $LASTEXITCODE" }
        throw "Failed to generate host keys: $details"
    }

    $existing = Get-ChildItem -Path $keyRoot -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue
    if (-not $existing -or $existing.Count -eq 0) {
        throw "Host keys were not created under '$keyRoot'."
    }
}
function Set-StrictFileSystemAcl {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][array]$Rules,
        [switch]$Directory,
        [string]$OwnerSid = 'S-1-5-18'
    )

    if (-not (Test-Path $Path)) { return }

    try {
        $acl = Get-Acl -Path $Path -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)

        foreach ($existing in @($acl.Access)) {
            [void]$acl.RemoveAccessRuleAll($existing)
        }

        if ($OwnerSid) {
            $owner = New-Object System.Security.Principal.SecurityIdentifier($OwnerSid)
            $acl.SetOwner($owner)
        }

        $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::None
        $propagationFlags = [System.Security.AccessControl.PropagationFlags]::None
        if ($Directory) {
            $inheritanceFlags = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
                                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        }

        foreach ($rule in $Rules) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($rule.Sid)
            $rights = [System.Security.AccessControl.FileSystemRights]$rule.Rights
            $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid,
                $rights,
                $inheritanceFlags,
                $propagationFlags,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            [void]$acl.AddAccessRule($accessRule)
        }

        Set-Acl -Path $Path -AclObject $acl -ErrorAction Stop
    }
    catch {
        throw "Failed to set ACL for '$Path': $($_.Exception.Message)"
    }
}

function Repair-OpenSSHDataPermissions {
    param([Parameter(Mandatory)][string]$ConfigPath)

    Write-Log -Level Info -Message "Repairing OpenSSH data permissions..."

    $sshRoot = Join-Path $env:ProgramData 'ssh'
    if (-not (Test-Path $sshRoot)) {
        New-Item -ItemType Directory -Path $sshRoot -Force | Out-Null
    }

    $logsDir = Join-Path $sshRoot 'logs'
    if (-not (Test-Path $logsDir)) {
        New-Item -ItemType Directory -Path $logsDir -Force | Out-Null
    }

    $systemAdminRules = @(
        @{ Sid = 'S-1-5-18'; Rights = 'FullControl' },
        @{ Sid = 'S-1-5-32-544'; Rights = 'FullControl' }
    )

    Set-StrictFileSystemAcl -Path $sshRoot -Rules $systemAdminRules -Directory
    Set-StrictFileSystemAcl -Path $logsDir -Rules $systemAdminRules -Directory
    Set-StrictFileSystemAcl -Path $ConfigPath -Rules $systemAdminRules

    $privateKeys = Get-ChildItem -Path $sshRoot -Filter 'ssh_host_*_key' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike '*.pub' }
    foreach ($keyFile in $privateKeys) {
        Set-StrictFileSystemAcl -Path $keyFile.FullName -Rules $systemAdminRules
    }

    $adminAuthKeys = Join-Path $sshRoot 'administrators_authorized_keys'
    if (Test-Path $adminAuthKeys) {
        Set-StrictFileSystemAcl -Path $adminAuthKeys -Rules $systemAdminRules
    }
}

function Test-SSHDConfig {
    param([Parameter(Mandatory)][string]$ConfigPath)

    if (-not (Test-Path $ConfigPath)) {
        throw "sshd_config not found at '$ConfigPath'."
    }

    $sshdExe = Get-SSHDExecutablePath
    if (-not $sshdExe) {
        throw "Cannot find sshd.exe after OpenSSH.Server installation."
    }

    $output = & $sshdExe -t -f $ConfigPath 2>&1
    if ($LASTEXITCODE -ne 0) {
        $code = [int]$LASTEXITCODE
        $hex = Get-ExitHex -Code $code
        $details = (($output | Where-Object { $_ }) -join ' | ')
        if (-not $details) { $details = "sshd exited with code $code ($hex)" }
        throw "sshd_config validation failed (code: $code / $hex): $details"
    }
}

function Set-SSHDService {
    param([switch]$ApplyConfig)

    Write-Log -Level Info -Message "Ensuring sshd service startup is automatic..."
    try {
        $sshdExe = Get-SSHDExecutablePath
        if (-not $sshdExe) {
            throw "Cannot find sshd.exe after OpenSSH.Server installation."
        }

        $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop

        if (-not $svc.PathName -or $svc.PathName -notmatch [regex]::Escape($sshdExe)) {
            Write-Log -Level Warn -Message "sshd service binary path is unexpected. Resetting to '$sshdExe'."
            sc.exe config sshd binPath= "`"$sshdExe`"" | Out-Null
            $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
        }

        if ($svc.StartName -ne 'LocalSystem') {
            Write-Log -Level Warn -Message "sshd service account is '$($svc.StartName)'. Resetting to LocalSystem."
            sc.exe config sshd obj= LocalSystem password= "" | Out-Null
            $svc = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction Stop
        }

        if ($svc.StartMode -ne 'Auto') {
            sc.exe config sshd start= auto | Out-Null
        }

        sc.exe sidtype sshd unrestricted | Out-Null

        if ($ApplyConfig) {
            Write-Log -Level Info -Message "Applying SSH service changes..."
            if ($svc.State -eq 'Running') {
                Restart-Service sshd -Force -ErrorAction Stop
            }
            else {
                Start-Service sshd -ErrorAction Stop
            }
        }
    }
    catch {
        $diag = $null
        try {
            $diagParts = @()
            $svcNow = Get-CimInstance Win32_Service -Filter "Name='sshd'" -ErrorAction SilentlyContinue
            if ($svcNow) {
                $diagParts += "State=$($svcNow.State)"
                $diagParts += "StartName=$($svcNow.StartName)"
                $diagParts += "StartMode=$($svcNow.StartMode)"
                $diagParts += "ExitCode=$($svcNow.ExitCode)"
                $diagParts += "PathName=$($svcNow.PathName)"
            }

            $sysEvt = Get-WinEvent -LogName System -MaxEvents 100 -ErrorAction SilentlyContinue |
                Where-Object { $_.Id -in 7000,7001,7009,7031,7034,7041 -and $_.Message -match 'sshd' } |
                Select-Object -First 1
            if ($sysEvt) {
                $sysMsg = (($sysEvt.Message -replace '\s+', ' ').Trim())
                $diagParts += "SystemEvent[$($sysEvt.Id)] $sysMsg"
            }

            $appEvt = Get-WinEvent -LogName Application -MaxEvents 150 -ErrorAction SilentlyContinue |
                Where-Object { $_.Id -eq 1000 -and $_.Message -match 'sshd\.exe' } |
                Select-Object -First 1
            if ($appEvt) {
                $appMsg = (($appEvt.Message -replace '\s+', ' ').Trim())
                $diagParts += "AppEvent[$($appEvt.Id)] $appMsg"
            }

            if ($diagParts.Count -gt 0) {
                $diag = $diagParts -join ' | '
            }
        }
        catch {
            # Best-effort diagnostics
        }

        if ($diag) {
            throw "Failed to configure sshd service: $($_.Exception.Message). Diagnostics: $diag"
        }
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
        if (-not (Test-Path $path)) {
            New-Item -Path $path -Force | Out-Null
        }
        Set-ItemProperty -Path $path -Name 'DefaultShell' -Value $ShellPath -Type String -Force
    }
    catch {
        Write-Log -Level Warn -Message "Failed to set DefaultShell: $($_.Exception.Message)"
    }
}

function Set-SSHFirewallRule {
    param([Parameter(Mandatory)][int]$Port)

    $ruleName = "OpenSSH-SSH-$Port"
    $existingRule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue

    if ($existingRule) {
        Write-Log -Level Info -Message "Firewall rule '$ruleName' already exists. Ensuring correct settings..."
        $existingRule | Set-NetFirewallRule -Direction Inbound -Action Allow -Profile Domain,Private,Public | Out-Null
        Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existingRule |
            Set-NetFirewallPortFilter -LocalPort $Port -Protocol TCP | Out-Null
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
            -Profile Domain,Private,Public | Out-Null
    }
}
function Resolve-LocalUserProfilePath {
    param([Parameter(Mandatory)][string]$UserName)

    $user = Get-LocalUser -Name $UserName -ErrorAction Stop
    $sid = $user.SID.Value
    $userProfile = Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.SID -eq $sid } |
        Select-Object -First 1
    if ($userProfile -and $userProfile.LocalPath) {
        return $userProfile.LocalPath
    }
    return "C:\Users\$UserName"
}

function Test-IsLocalAdministrator {
    param([Parameter(Mandatory)][string]$UserName)
    try {
        $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
        return [bool]($admins | Where-Object { $_.Name -match "\\$([regex]::Escape($UserName))$" })
    }
    catch {
        return $false
    }
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

    $key = (Get-Content -Path $PublicKeyFile -Raw).Trim()
    if (-not $key) {
        throw "Public key file is empty: $PublicKeyFile"
    }

    $targetIsAdmin = Test-IsLocalAdministrator -UserName $TargetUser
    $sshRoot = Join-Path $env:ProgramData 'ssh'

    if ($AuthorizedKeysPath) {
        $authKeys = $AuthorizedKeysPath
    }
    elseif ($targetIsAdmin) {
        $authKeys = Join-Path $sshRoot 'administrators_authorized_keys'
    }
    else {
        $profilePath = Resolve-LocalUserProfilePath -UserName $TargetUser
        $sshDir = Join-Path $profilePath '.ssh'
        if (-not (Test-Path $sshDir)) {
            New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
        }
        $authKeys = Join-Path $sshDir 'authorized_keys'
    }

    $authDir = Split-Path -Parent $authKeys
    if ($authDir -and -not (Test-Path $authDir)) {
        New-Item -ItemType Directory -Path $authDir -Force | Out-Null
    }
    if (-not (Test-Path $authKeys)) {
        New-Item -ItemType File -Path $authKeys -Force | Out-Null
    }

    $existing = Get-Content -Path $authKeys -ErrorAction SilentlyContinue
    if ($existing -notcontains $key) {
        Add-Content -Path $authKeys -Value $key -Encoding Ascii
    }

    if ($targetIsAdmin -and -not $AuthorizedKeysPath) {
        $systemAdminRules = @(
            @{ Sid = 'S-1-5-18'; Rights = 'FullControl' },
            @{ Sid = 'S-1-5-32-544'; Rights = 'FullControl' }
        )
        Set-StrictFileSystemAcl -Path $authKeys -Rules $systemAdminRules
    }
    else {
        $user = Get-LocalUser -Name $TargetUser -ErrorAction Stop
        $userSid = $user.SID.Value
        $fileRules = @(
            @{ Sid = $userSid;        Rights = 'ReadAndExecute' },
            @{ Sid = 'S-1-5-18';      Rights = 'FullControl' },
            @{ Sid = 'S-1-5-32-544';  Rights = 'FullControl' }
        )
        Set-StrictFileSystemAcl -Path $authKeys -Rules $fileRules

        $sshDir = Split-Path -Parent $authKeys
        if ($sshDir) {
            $dirRules = @(
                @{ Sid = $userSid;        Rights = 'FullControl' },
                @{ Sid = 'S-1-5-18';      Rights = 'FullControl' },
                @{ Sid = 'S-1-5-32-544';  Rights = 'FullControl' }
            )
            Set-StrictFileSystemAcl -Path $sshDir -Rules $dirRules -Directory -OwnerSid $userSid
        }
    }
}

function Hide-UserFromLogonUI {
    param([Parameter(Mandatory)][string]$UserName)
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
    }
    New-ItemProperty -Path $regPath -Name $UserName -PropertyType DWord -Value 0 -Force | Out-Null
}

function New-AnsibleServiceUser {
    param(
        [Parameter(Mandatory)][string]$UserName,
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
            Write-Log -Level Warn -Message "ServiceUserPass passed on command line can leak via process args. Prefer -ServiceUserPassFile."
            $plain = $PlainPassword
        }

        if (-not $plain) {
            Add-Type -AssemblyName System.Web
            $plain = [System.Web.Security.Membership]::GeneratePassword(32, 6)
        }

        $securePassword = ConvertTo-SecureString $plain -AsPlainText -Force
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

    Add-LocalGroupMember -Group 'Administrators' -Member $UserName -ErrorAction SilentlyContinue
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
                if ($nt -match '^S-1-') { $nt = "*$nt" }
                $set[$nt.ToUpperInvariant()] = $true
            }
            if (-not $set.ContainsKey($sidToken.ToUpperInvariant())) {
                $tokens += $sidToken
            }
            "$lhs" + ($tokens -join ',')
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
                if ($nt -match '^S-1-') { $nt = "*$nt" }
                $set[$nt.ToUpperInvariant()] = $true
            }
            if (-not $set.ContainsKey($sidToken.ToUpperInvariant())) {
                $tokens += $sidToken
            }
            "$lhs" + ($tokens -join ',')
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
Set-DefaultShell -ShellPath $DefaultShell

$sshdConfig = Join-Path $env:ProgramData 'ssh\sshd_config'
Set-SSHDConfig `
    -ConfigPath $sshdConfig `
    -Port $Port `
    -PasswordAuth:$AllowPasswordAuth `
    -PubkeyAuth:$true `
    -AllowSftp:$AllowSftp `
    -AllowUsers $AllowUsers

Set-SSHHostKeys
Repair-OpenSSHDataPermissions -ConfigPath $sshdConfig

try {
    Test-SSHDConfig -ConfigPath $sshdConfig
}
catch {
    if ($_.Exception.Message -match '0xC0000139|-1073741511') {
        Write-Log -Level Warn -Message "Detected OpenSSH binary mismatch crash (STATUS_ENTRYPOINT_NOT_FOUND). Reinstalling OpenSSH.Server once..."
        Set-OpenSSHInstalled -ForceReinstall
        Set-SSHDConfig `
            -ConfigPath $sshdConfig `
            -Port $Port `
            -PasswordAuth:$AllowPasswordAuth `
            -PubkeyAuth:$true `
            -AllowSftp:$AllowSftp `
            -AllowUsers $AllowUsers
        Set-SSHHostKeys
        Repair-OpenSSHDataPermissions -ConfigPath $sshdConfig
        Test-SSHDConfig -ConfigPath $sshdConfig
    }
    else {
        throw
    }
}

if ($NewUser -and $PublicKeyFile) {
    Set-AuthorizedKeys -TargetUser $ServiceUserName -PublicKeyFile $PublicKeyFile -AuthorizedKeysPath $AuthorizedKeysPath
}
elseif ($PublicKeyFile -and $AllowUsers -and $AllowUsers.Count -eq 1) {
    Set-AuthorizedKeys -TargetUser $AllowUsers[0] -PublicKeyFile $PublicKeyFile -AuthorizedKeysPath $AuthorizedKeysPath
}

Set-SSHFirewallRule -Port $Port
Set-SSHDService -ApplyConfig

Write-Log -Level Info -Message "=== OpenSSH configuration complete ==="
Write-Log -Level Info -Message "Port: $Port"
Write-Log -Level Info -Message "PasswordAuthentication: $AllowPasswordAuth"
Write-Log -Level Info -Message "PubkeyAuthentication: $true"
Write-Log -Level Info -Message "AllowUsers: $(if ($AllowUsers) { $AllowUsers -join ',' } else { '(all)' })"

exit $script:ExitCode
