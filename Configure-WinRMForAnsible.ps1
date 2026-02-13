<#
.SYNOPSIS
  Fully configures a Windows host for Ansible remoting via WinRM,
  even when network profile is set to Public.

.DESCRIPTION
  - Applies persistent WinRM policy registry keys
  - Enables and starts WinRM service
  - Creates listeners (HTTP default, HTTPS optional)
  - Adds firewall rules for all network profiles
  - Configures authentication and TrustedHosts
  - Auto-manages HTTPS certificate lifecycle (create/renew/cleanup) when -UseHTTPS is used
  - Optionally creates a local non-interactive admin service user when -NewUser is used
  - Writes structured logs to file (and optional Event Log) with friendly console output
  - No user interaction required
#>

param(
    [switch]$UseHTTPS,
    [string]$TrustedHosts = "*",
    [int]$Port,
    [switch]$EncryptedOnly,
    [switch]$SkipNetworkFix,
    [switch]$EnableCredSSP,
    [string]$LogPath,
    [ValidateSet('text','json')]
    [string]$LogFormat = 'text',
    [switch]$DisableEventLog,
    [switch]$FullErrors,
    # -------------------------------
    # Service user creation
    # -------------------------------
    [switch]$NewUser,
    [string]$ServiceUserName = "ansible_svc",

    # Optional manual password (simplest, but leaks via command line in many agents)
    [string]$ServiceUserPass,

    # Optional password file (recommended if your agent can stage a file)
    [string]$ServiceUserPassFile
)

# -------------------------------------------------------------------
# CI-friendly defaults and logging
# -------------------------------------------------------------------
$ProgressPreference = 'SilentlyContinue'
$ConfirmPreference = 'None'

$script:EventSource = 'Configure-WinRMForAnsible'
$script:EventLogEnabled = $false
$script:LogFileEnabled = $false
$script:LogFilePath = $null
$script:LogPath = $LogPath
$script:LogFormat = $LogFormat
$script:DisableEventLog = $DisableEventLog
$script:FriendlyErrors = -not $FullErrors
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

    $root = Join-Path $env:ProgramData 'Configure-WinRMForAnsible'
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
        Join-Path $env:ProgramData 'Configure-WinRMForAnsible\Configure-WinRMForAnsible.log'
    }

    try {
        if (-not $script:IsAdmin -and -not $script:LogPath) {
            # Default machine-wide log is for elevated runs only unless explicitly overridden.
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
                'Info'  { 1000 }
                'Warn'  { 1001 }
                'Error' { 1002 }
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
function Set-WinRMFirewallRule {
    param (
        [Parameter(Mandatory)]
        [ValidateSet('HTTP','HTTPS')]
        [string]$Transport,

        [Parameter(Mandatory)]
        [int]$Port
    )

    $ruleName = "WinRM-$Transport-$Port"

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
            -Description "Allow WinRM $Transport ($Port) for Ansible" `
            -Direction Inbound `
            -Protocol TCP `
            -LocalPort $Port `
            -Action Allow `
            -Profile Domain,Private,Public |
            Out-Null
    }
}

# -------------------------------------------------------------------
# Registry helper
# -------------------------------------------------------------------
function Set-RegistryValue {
    param (
        [Parameter(Mandatory)]
        [string] $Path,

        [Parameter(Mandatory)]
        [string] $Name,

        [Parameter(Mandatory)]
        [object] $Value,

        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryValueKind] $Type,

        [string] $ChangeLabel
    )

    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }

        $current = (Get-ItemProperty `
            -Path $Path `
            -Name $Name `
            -ErrorAction SilentlyContinue
        ).$Name

        if ($current -ne $Value) {
            New-ItemProperty `
                -Path $Path `
                -Name $Name `
                -Value $Value `
                -PropertyType $Type `
                -Force `
                -ErrorAction Stop | Out-Null

            if ($ChangeLabel) { $script:RegChanges += $ChangeLabel }
        }
    }
    catch {
        throw "Failed to configure registry value '$Name' at '$Path': $($_.Exception.Message)"
    }
}

function Disable-LockScreen {
    $path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
    if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
    New-ItemProperty -Path $path -Name 'NoLockScreen' -PropertyType DWord -Value 1 -Force | Out-Null
}

function Test-HasOtherInteractiveSessions {
    param([string]$AllowedUser)

    $out = (query session) 2>$null
    if (-not $out) { return $false }

    foreach ($line in $out) {
        # ignore headers
        if ($line -match '^\s*SESSIONNAME\s+USERNAME') { continue }

        # interested in sessions that have a USERNAME
        # Match: username ... id ... state
        $m = [regex]::Match($line, '^\s*(\S+)\s+(\S+)\s+(\d+)\s+(\S+)')
        if ($m.Success) {
            $user = $m.Groups[2].Value
            $state = $m.Groups[4].Value

            # If another user has an Active/Disc session, be conservative and do nothing
            if ($user -and $user -ne $AllowedUser -and $state -match 'Active|Disc') {
                return $true
            }
        }
    }

    return $false
}

# -------------------------------------------------------------------
# Hide user from Windows sign-in screen
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

    # DWORD 0 = hide, 1 = show
    New-ItemProperty -Path $regPath -Name $UserName -PropertyType DWord -Value 0 -Force | Out-Null
}

# -------------------------------------------------------------------
# Create non-interactive local service user (optional)
# -------------------------------------------------------------------
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

        # Decide password source (priority: file -> direct param -> autogenerated)
        $plain = $null

        if ($PasswordFile) {
            if (-not (Test-Path $PasswordFile)) {
                throw "Password file not found: $PasswordFile"
            }
            $plain = (Get-Content $PasswordFile -Raw).Trim()

            # best-effort cleanup to reduce secret lifetime
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

        # Create user
        New-LocalUser `
            -Name $UserName `
            -Password $securePassword `
            -Description "Ansible WinRM service account" `
            -PasswordNeverExpires `
            -UserMayNotChangePassword | Out-Null

        Write-Log -Level Info -Message "User '$UserName' created."
    }
    else {
        Write-Log -Level Info -Message "User '$UserName' already exists. Applying hardening..."
    }

    # Add to Administrators (your original line kept)
    Add-LocalGroupMember -Group "Administrators" -Member $UserName -ErrorAction SilentlyContinue

    # Ensure enabled
    Enable-LocalUser -Name $UserName -ErrorAction SilentlyContinue

    # Deny interactive and RDP logon (improved)
    try {
        $lu = Get-LocalUser -Name $UserName -ErrorAction Stop
        $sidToken = "*$($lu.SID.Value)"   # secedit user-rights expect *SID tokens
        $tmp = "$env:TEMP\secpol-ansible.cfg"

        secedit /export /cfg $tmp | Out-Null

        # secedit exports Unicode; read Unicode for correctness
        $content = Get-Content $tmp -Encoding Unicode

        # Ensure keys exist; if not, add them.
        if ($content -notmatch '^SeDenyInteractiveLogonRight') {
            $content += "SeDenyInteractiveLogonRight ="
        }
        if ($content -notmatch '^SeDenyRemoteInteractiveLogonRight') {
            $content += "SeDenyRemoteInteractiveLogonRight ="
        }

        # Append token if missing (Interactive logon)
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
                if ($nt -match "^S-1-") { $nt = "*$nt" }   # normalize
                $set[$nt.ToUpperInvariant()] = $true
            }

            if (-not $set.ContainsKey($sidToken.ToUpperInvariant())) {
                $tokens += $sidToken
            }

            "$lhs" + ($tokens -join ",")
        }

        # Append token if missing (Remote interactive / RDP)
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

        # Write back as Unicode, then apply
        $content | Set-Content $tmp -Encoding Unicode
        secedit /configure /db secedit.sdb /cfg $tmp /areas USER_RIGHTS | Out-Null
    }
    catch {
        Write-Log -Level Warn -Message "Failed to apply logon restrictions for '$UserName': $($_.Exception.Message)"
    }

    # Hide from Windows logon UI (so it won't appear as a login option)
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

$AllowUnencryptedEffective = -not $EncryptedOnly

# -------------------------------------------------------------------
# Preserve sign-in UX (conservative): detect pre-state BEFORE creating service user
# -------------------------------------------------------------------
$script:PreserveNoClickUX = $false

# Skip on domain-joined systems
$domainJoined = $false
try {
    $cs = Get-CimInstance Win32_ComputerSystem
    $domainJoined = [bool]$cs.PartOfDomain
} catch {}

# Skip if lock screen already managed by policy/GPO
$polPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'
$lockPolicyManaged = $false
try {
    $null = Get-ItemProperty -Path $polPath -Name 'NoLockScreen' -ErrorAction Stop
    $lockPolicyManaged = $true
} catch {}

if (-not $domainJoined -and -not $lockPolicyManaged) {
    try {
        # enabled local users excluding built-ins and the service user name (even if it exists already)
        $preUsers = Get-LocalUser | Where-Object {
            $_.Enabled -eq $true -and
            $_.Name -notin @('Administrator','Guest','DefaultAccount','WDAGUtilityAccount') -and
            $_.Name -ne $ServiceUserName
        }

        if ($preUsers.Count -eq 1) {
            $u = $preUsers[0]

            # Very conservative: only if password is NOT required (your case)
            if ($u.PasswordRequired -eq $false) {

                # Also conservative: do nothing if there are other interactive sessions around
                if (-not (Test-HasOtherInteractiveSessions -AllowedUser $u.Name)) {
                    $script:PreserveNoClickUX = $true
                    $script:PrimaryInteractiveUser = $u.Name
                }
            }
        }
    } catch {}
}

if ($NewUser) {
    New-AnsibleServiceUser `
        -UserName $ServiceUserName `
        -PlainPassword $ServiceUserPass `
        -PasswordFile $ServiceUserPassFile
}

# Restore prior single-user no-click UX only when we are very sure it existed
if ($script:PreserveNoClickUX) {
    try {
        Disable-LockScreen
        Write-Log -Level Info -Message "Preserved no-click sign-in UX for '$script:PrimaryInteractiveUser' (Lock Screen disabled)."
    } catch {
        Write-Log -Level Warn -Message "Could not preserve sign-in UX: $($_.Exception.Message)"
    }
}

# -------------------------------------------------------------------
# Default port assignment
# -------------------------------------------------------------------
if (-not $Port) {
    $Port = if ($UseHTTPS) { 5986 } else { 5985 }
}

Write-Log -Level Info -Message "=== Configuring WinRM for Ansible ==="

# -------------------------------------------------------------------
# Handle systems with Public network profiles early
# -------------------------------------------------------------------
if (-not $SkipNetworkFix) {
    Write-Log -Level Info -Message "Checking network profile..."
    $publicNetworks = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq "Public"}
    if ($publicNetworks) {
        foreach ($p in $publicNetworks) {
            Write-Log -Level Info -Message "Public network detected for '$($p.Name)'. Switching to Private to allow WinRM configuration..."
            try {
                Set-NetConnectionProfile -Name $p.Name -NetworkCategory Private -ErrorAction Stop
            } catch {
                Write-Log -Level Warn -Message "Failed to change network '$($p.Name)': $_"
            }
        }
        Start-Sleep 2
    }
}

# -------------------------------------------------------------------
# Apply persistent WinRM policy keys
# -------------------------------------------------------------------
Write-Log -Level Info -Message "Ensuring WinRM policy registry settings are correctly configured..."

$script:RegChanges = @()

$basePath  = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service'
$winrsPath = 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS'

# --- WinRM Service policies ---
Set-RegistryValue `
    -Path $basePath `
    -Name 'AllowBasic' `
    -Value 1 `
    -Type DWord `
    -ChangeLabel 'AllowBasic'

Set-RegistryValue `
    -Path $basePath `
    -Name 'AllowAutoConfig' `
    -Value 1 `
    -Type DWord `
    -ChangeLabel 'AllowAutoConfig'

if ($AllowUnencryptedEffective) {
    Set-RegistryValue `
        -Path $basePath `
        -Name 'AllowUnencryptedTraffic' `
        -Value 1 `
        -Type DWord `
        -ChangeLabel 'AllowUnencryptedTraffic'
}

# --- WinRS policies ---
Set-RegistryValue `
    -Path $winrsPath `
    -Name 'AllowRemoteShellAccess' `
    -Value 1 `
    -Type DWord `
    -ChangeLabel 'AllowRemoteShellAccess'

# --- UAC local token filter ---
Set-RegistryValue `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' `
    -Value 1 `
    -Type DWord `
    -ChangeLabel 'LocalAccountTokenFilterPolicy'

# --- Output ---
if ($RegChanges.Count -eq 0) {
    Write-Log -Level Info -Message "WinRM policy registry settings already correct"
}
else {
    Write-Log -Level Info -Message ("WinRM policy registry updated (" + ($RegChanges -join ', ') + ")")
}

# -------------------------------------------------------------------
# Optimize certificate checks for offline/local networks (machine-wide)
# Avoids slow CRL/OCSP online checks for self-signed certs (reduces boot delay)
# -------------------------------------------------------------------
try {
    Write-Log -Level Info -Message "Applying machine-wide WinTrust optimization to reduce online CRL checks..."
    $wk = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
    if (-not (Test-Path $wk)) { New-Item -Path $wk -Force | Out-Null }
    # Value 146944 reduces strict online revocation checks (helps booting offline)
    Set-ItemProperty -Path $wk -Name "State" -Value 146944 -Type DWord -Force
} catch {
    Write-Log -Level Warn -Message "Could not apply WinTrust optimization: $_"
}

# -------------------------------------------------------------------
# Enable PS Remoting / WinRM service
# -------------------------------------------------------------------
Write-Log -Level Info -Message "Ensuring WinRM service is correctly configured..."

try {
    $changes = @()

    # Always enforce dependencies (cannot be reliably detected)
    sc.exe config winrm depend= http/cryptsvc | Out-Null

    $svc = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop

    # --- Startup type (Delayed Auto) ---
    if ($svc.StartMode -ne 'Auto' -or -not $svc.DelayedAutoStart) {
        sc.exe config winrm start= delayed-auto | Out-Null
        $changes += 'startup type'
    }

    # --- Running state ---
    if ($svc.State -ne 'Running') {
        Start-Service WinRM -ErrorAction Stop
        $changes += 'service started'
    }

    # --- Output ---
    if ($changes.Count -eq 0) {
        Write-Log -Level Info -Message "WinRM already configured and running"
    }
    else {
        Write-Log -Level Info -Message ("WinRM updated (" + ($changes -join ', ') + ")")
    }
}
catch {
    Write-Log -Level Warn -Message "WinRM configuration failed: $($_.Exception.Message)"
}

# -------------------------------------------------------------------
# Create listener(s) (HTTPS optional) and manage HTTPS cert lifecycle
# -------------------------------------------------------------------
if ($UseHTTPS) {
    Write-Log -Level Info -Message "Configuring HTTPS listener on port $Port..."

        # --- Self-healing cleanup for stale HTTPS listeners or mismatched certs ---
        Write-Log -Level Info -Message "Ensuring WinRM HTTPS listener and certificate are valid..."

        $hostname  = $env:COMPUTERNAME
        $now       = Get-Date

        # Get primary IPv4 (stable, non-APIPA)
        $primaryIP = Get-NetIPAddress -AddressFamily IPv4 |
            Where-Object {
                $_.IPAddress -notmatch '^169\.254' -and
                $_.IPAddress -ne '127.0.0.1' -and
                $_.PrefixOrigin -ne 'WellKnown'
            } |
            Select-Object -ExpandProperty IPAddress -First 1

        # ------------------------------------------------------------
        # Read existing HTTPS listener (do NOT delete blindly)
        # ------------------------------------------------------------
        $listenerText = winrm get winrm/config/Listener?Address=*+Transport=HTTPS 2>$null
        $currentThumb = $null

        $thumbLine = $listenerText | Select-String 'CertificateThumbprint'
        if ($thumbLine -and $thumbLine.Line -match '=\s*([A-F0-9]{40})') {
            $currentThumb = $Matches[1]
        }
        # ------------------------------------------------------------
        # Try to reuse an existing valid certificate
        # ------------------------------------------------------------
        $cert = $null

        if ($currentThumb) {
            $cert = Get-ChildItem "Cert:\LocalMachine\My\$currentThumb" -ErrorAction SilentlyContinue
        }

        if (-not $cert) {
            $cert = Get-ChildItem Cert:\LocalMachine\My |
                Where-Object {
                    $_.FriendlyName -eq 'WinRM HTTPS for Ansible' -and
                    $_.NotAfter -gt $now
                } |
                Sort-Object NotAfter -Descending |
                Select-Object -First 1
        }

        # ------------------------------------------------------------
        # Validate cert hostname / SAN
        # ------------------------------------------------------------
        $certValid = $false

        if ($cert) {
            $certValid = $true

            if ($cert.Subject -notmatch [regex]::Escape($hostname) -and
                ($primaryIP -and $cert.Subject -notmatch [regex]::Escape($primaryIP))) {
                $certValid = $false
            }

            try {
                $san = ($cert.Extensions |
                    Where-Object { $_.Oid.FriendlyName -eq 'Subject Alternative Name' }
                ).Format($false)

                if ($san -and (
                    $san -match [regex]::Escape($hostname) -or
                    ($primaryIP -and $san -match [regex]::Escape($primaryIP))
                )) {
                    $certValid = $true
                }
            } catch {}
        }

        # ------------------------------------------------------------
        # Create cert ONLY if required
        # ------------------------------------------------------------
        if (-not $certValid) {
            Write-Log -Level Info -Message "Creating new self-signed certificate for WinRM HTTPS..."

            $dnsNames = @($hostname)

            $cert = New-SelfSignedCertificate `
                -DnsName $dnsNames `
                -CertStoreLocation 'Cert:\LocalMachine\My' `
                -FriendlyName 'WinRM HTTPS for Ansible' `
                -NotAfter ($now.AddYears(5))
        }

        # ------------------------------------------------------------
        # Ensure listener exists and is bound to correct cert
        # ------------------------------------------------------------
        $needsListener = $true

        if ($currentThumb -and $cert.Thumbprint -eq $currentThumb) {
            $needsListener = $false
        }

        if ($needsListener) {
            Write-Log -Level Info -Message "Binding certificate to WinRM HTTPS listener..."

            try {
                winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null | Out-Null
            } catch {}

            $listenerHostname = $hostname

            winrm create winrm/config/Listener?Address=*+Transport=HTTPS `
                "@{Hostname=`"$listenerHostname`";CertificateThumbprint=`"$($cert.Thumbprint)`";Port=`"$Port`"}" |
            Out-Null

        }

        # ------------------------------------------------------------
        # Safe cleanup: remove expired or truly unused WinRM certs
        # ------------------------------------------------------------
        try {
            Write-Log -Level Info -Message "Performing WinRM certificate cleanup..."

            if (-not $cert -or -not $cert.Thumbprint) {
                Write-Log -Level Warn -Message "Active WinRM certificate not identified; skipping cleanup to avoid accidental removal."
            } else {
                $boundThumbs = @($cert.Thumbprint)
                $removed     = @()

                Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop |
                    Where-Object {
                        $_.FriendlyName -eq 'WinRM HTTPS for Ansible' -and
                        (
                            $_.NotAfter -lt $now -or
                            $_.Thumbprint -notin $boundThumbs
                        )
                    } |
                    ForEach-Object {
                        try {
                            Write-Log -Level Info -Message "Removing stale WinRM certificate: $($_.Thumbprint)"
                            Remove-Item $_.PSPath -Force -ErrorAction Stop
                            $removed += $_.Thumbprint
                        } catch {
                            Write-Log -Level Warn -Message "Failed to remove certificate $($_.Thumbprint): $($_.Exception.Message)"
                        }
                    }

                if ($removed.Count -eq 0) {
                    Write-Log -Level Info -Message "No stale or expired WinRM certificates found."
                } else {
                    Write-Log -Level Info -Message "Removed WinRM certificates: $($removed -join ', ')"
                }
            }

        } catch {
            Write-Log -Level Warn -Message "WinRM certificate cleanup encountered an issue and was skipped: $($_.Exception.Message)"
        }

        Write-Log -Level Info -Message "WinRM HTTPS listener and certificate are valid."

        # Add HTTPS firewall rule idempotently
        Set-WinRMFirewallRule -Transport HTTPS -Port $Port

} else {
    Write-Log -Level Info -Message "Configuring HTTP listener on port $Port..."
    $httpListener = winrm enumerate winrm/config/listener 2>$null | Select-String "Transport = HTTP"
    if (-not $httpListener) {
        & winrm create winrm/config/Listener?Address=*+Transport=HTTP "@{Port=`"$Port`"}" | Out-Null
    } else {
        Write-Log -Level Info -Message "HTTP listener already exists."
    }

    # Add HTTP firewall rule idempotently
    Set-WinRMFirewallRule -Transport HTTP -Port $Port

}

# -------------------------------------------------------------------
# Configure WinRM authentication & transport settings
# -------------------------------------------------------------------
Write-Log -Level Info -Message "Ensuring WinRM authentication settings are correctly configured..."

try {
    $changes = @()

    # Helper: set WSMan value only if different
    function Set-WSManValue {
        param (
            [Parameter(Mandatory)]
            [string] $Path,

            [Parameter(Mandatory)]
            [bool] $DesiredValue,

            [string] $ChangeLabel
        )

        $current = Get-Item $Path -ErrorAction Stop

        if ([bool]$current.Value -ne $DesiredValue) {
            Set-Item $Path -Value $DesiredValue -ErrorAction Stop
            if ($ChangeLabel) { $changes += $ChangeLabel }
        }
    }

    # --- Authentication mechanisms ---
    Set-WSManValue 'WSMan:\localhost\Service\Auth\Basic'     $true 'Basic auth'
    Set-WSManValue 'WSMan:\localhost\Service\Auth\Negotiate' $true 'Negotiate auth'

    if ($EnableCredSSP) {
        Enable-WSManCredSSP -Role Server -Force | Out-Null
        Set-WSManValue 'WSMan:\localhost\Service\Auth\CredSSP' $true 'CredSSP'
    }
    else {
        Set-WSManValue 'WSMan:\localhost\Service\Auth\CredSSP' $false 'CredSSP disabled'
    }

    if ($AllowUnencryptedEffective -and -not $UseHTTPS) {
        try {
            Set-WSManValue 'WSMan:\localhost\Service\AllowUnencrypted' $true 'AllowUnencrypted'
        }
        catch {
            Write-Log -Level Warn -Message "Could not set AllowUnencrypted via WSMan provider; continuing"
        }
    }

    # --- Output ---
    if ($changes.Count -eq 0) {
        Write-Log -Level Info -Message "WinRM authentication settings already correct"
    }
    else {
        Write-Log -Level Info -Message ("WinRM authentication updated (" + ($changes -join ', ') + ")")
    }
}
catch {
    Write-Log -Level Warn -Message "WinRM authentication configuration failed: $($_.Exception.Message)"
}


# -------------------------------------------------------------------
# TrustedHosts configuration
# -------------------------------------------------------------------
if ($TrustedHosts) {
    try {
        $currentTrusted = (Get-Item WSMan:\localhost\Client\TrustedHosts -ErrorAction Stop).Value
        if ($currentTrusted -ne $TrustedHosts) {
            Write-Log -Level Info -Message "Setting TrustedHosts to '$TrustedHosts'..."
            Set-Item WSMan:\localhost\Client\TrustedHosts -Value $TrustedHosts -Force
        }
        else {
            Write-Log -Level Info -Message "TrustedHosts already set to '$TrustedHosts'"
        }
    }
    catch {
        Write-Log -Level Warn -Message "Failed to read current TrustedHosts; attempting to set anyway."
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value $TrustedHosts -Force
    }
}

# -------------------------------------------------------------------
# Restart WinRM and confirm
# -------------------------------------------------------------------
Restart-Service WinRM -Force

Write-Log -Level Info -Message "=== WinRM configuration complete ($(if ($UseHTTPS) {'HTTPS'} else {'HTTP'})) (Public network compatible) ==="
Write-Log -Level Info -Message "Port: $Port"
Write-Log -Level Info -Message "TrustedHosts: $TrustedHosts"
Write-Log -Level Info -Message "Unencrypted: $AllowUnencryptedEffective"
Write-Log -Level Info -Message "Auth: Basic=$true, Negotiate=$true, CredSSP=$EnableCredSSP"
if ($UseHTTPS) {
    $listenerText = winrm get winrm/config/Listener?Address=*+Transport=HTTPS 2>$null
    $thumbLine = $listenerText | Select-String 'CertificateThumbprint'
    $curThumb = $null
    if ($thumbLine -and $thumbLine.Line -match '=\s*([A-F0-9]{40})') { $curThumb = $Matches[1] }
    Write-Log -Level Info -Message "Certificate Thumbprint: $curThumb"
}

exit $script:ExitCode
