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
  - No user interaction required
#>

param(
    [switch]$UseHTTPS,
    [string]$TrustedHosts = "*",
    [int]$Port,
    [switch]$AllowUnencrypted = $true,
    [switch]$SkipNetworkFix = $false,
    [switch]$EnableCredSSP = $false
)

if (-not $Port) {
    $Port = if ($UseHTTPS) { 5986 } else { 5985 }
}

Write-Host "=== Configuring WinRM for Ansible ===" -ForegroundColor Cyan

# -------------------------------------------------------------------
# 4. Firewall rules for all profiles (Domain, Private, Public) - ensure rule exists and applies to all profiles
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
        Write-Host "Firewall rule '$ruleName' already exists. Ensuring correct settings..."
        $existingRule |
            Set-NetFirewallRule -Profile Domain,Private,Public -Direction Inbound -Action Allow |
            Out-Null

        Get-NetFirewallPortFilter -AssociatedNetFirewallRule $existingRule |
            Set-NetFirewallPortFilter -LocalPort $Port -Protocol TCP |
            Out-Null
    }
    else {
        Write-Host "Creating firewall rule '$ruleName'..."
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
# 0. Fix: handle systems with Public network profiles early
# -------------------------------------------------------------------
if (-not $SkipNetworkFix) {
    Write-Host "Checking network profile..."
    $publicNetworks = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq "Public"}
    if ($publicNetworks) {
        foreach ($p in $publicNetworks) {
            Write-Host "Public network detected for '$($p.Name)'. Switching to Private to allow WinRM configuration..." -ForegroundColor Yellow
            try {
                Set-NetConnectionProfile -Name $p.Name -NetworkCategory Private -ErrorAction Stop
            } catch {
                Write-Warning "Failed to change network '$($p.Name)': $_"
            }
        }
        Start-Sleep 2
    }
}

# -------------------------------------------------------------------
# 1. Apply persistent WinRM policy keys
# -------------------------------------------------------------------

function Set-RegistryValue {
    param (
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [object]$Value,

        [Parameter(Mandatory)]
        [Microsoft.Win32.RegistryValueKind]$Type
    )

    try {
        if (-not (Test-Path $Path)) {
            Write-Host "Creating registry path: $Path"
            New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
        }

        $currentValue = (Get-ItemProperty `
            -Path $Path `
            -Name $Name `
            -ErrorAction SilentlyContinue
        ).$Name

        if ($currentValue -ne $Value) {
            Write-Host "Setting $Path\$Name = $Value"
            New-ItemProperty `
                -Path $Path `
                -Name $Name `
                -Value $Value `
                -PropertyType $Type `
                -Force `
                -ErrorAction Stop | Out-Null
        }
        else {
            Write-Host "$Path\$Name already set correctly"
        }
    }
    catch {
        Write-Error "Failed to configure registry value '$Name' at '$Path': $($_.Exception.Message)"
        throw
    }
}

Write-Host "Checking WinRM policy registry keys..."

$basePath  = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"
$winrsPath = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS"

# --- WinRM Service policies ---
Set-RegistryValue `
    -Path $basePath `
    -Name "AllowBasic" `
    -Value 1 `
    -Type DWord

Set-RegistryValue `
    -Path $basePath `
    -Name "AllowAutoConfig" `
    -Value 1 `
    -Type DWord

if ($AllowUnencrypted) {
    Set-RegistryValue `
        -Path $basePath `
        -Name "AllowUnencryptedTraffic" `
        -Value 1 `
        -Type DWord
}

# --- WinRS policies ---
Set-RegistryValue `
    -Path $winrsPath `
    -Name "AllowRemoteShellAccess" `
    -Value 1 `
    -Type DWord

# --- UAC local token filter ---
Set-RegistryValue `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' `
    -Value 1 `
    -Type DWord

# -------------------------------------------------------------------
# Optimize certificate checks for offline/local networks (machine-wide)
# Avoids slow CRL/OCSP online checks for self-signed certs (reduces boot delay)
# -------------------------------------------------------------------
try {
    Write-Host "Applying machine-wide WinTrust optimization to reduce online CRL checks..."
    $wk = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WinTrust\Trust Providers\Software Publishing"
    if (-not (Test-Path $wk)) { New-Item -Path $wk -Force | Out-Null }
    # Value 146944 reduces strict online revocation checks (helps booting offline)
    Set-ItemProperty -Path $wk -Name "State" -Value 146944 -Type DWord -Force
} catch {
    Write-Warning "Could not apply WinTrust optimization: $_"
}

# -------------------------------------------------------------------
# 2. Enable PS Remoting / WinRM service
# -------------------------------------------------------------------
Write-Host "Ensuring WinRM service is correctly configured..."

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
        Write-Host "WinRM already configured and running"
    }
    else {
        Write-Host "WinRM updated (" + ($changes -join ', ') + ")"
    }
}
catch {
    Write-Warning "WinRM configuration failed: $($_.Exception.Message)"
}

# -------------------------------------------------------------------
# 3. Create listener(s) (HTTPS optional) and manage HTTPS cert lifecycle
# -------------------------------------------------------------------
if ($UseHTTPS) {
    Write-Host "Configuring HTTPS listener on port $Port..."

        # --- Self-healing cleanup for stale HTTPS listeners or mismatched certs ---
        Write-Host "Ensuring WinRM HTTPS listener and certificate are valid..." -ForegroundColor Cyan

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
        # 1. Read existing HTTPS listener (do NOT delete blindly)
        # ------------------------------------------------------------
        $listenerText = winrm get winrm/config/Listener?Address=*+Transport=HTTPS 2>$null
        $currentThumb = $null

        $thumbLine = $listenerText | Select-String 'CertificateThumbprint'
        if ($thumbLine -and $thumbLine.Line -match '=\s*([A-F0-9]{40})') {
            $currentThumb = $Matches[1]
        }
        # ------------------------------------------------------------
        # 2. Try to reuse an existing valid certificate
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
        # 3. Validate cert hostname / SAN
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
        # 4. Create cert ONLY if required
        # ------------------------------------------------------------
        if (-not $certValid) {
            Write-Host "Creating new self-signed certificate for WinRM HTTPS..." -ForegroundColor Yellow

            $dnsNames = @($hostname)

            $cert = New-SelfSignedCertificate `
                -DnsName $dnsNames `
                -CertStoreLocation 'Cert:\LocalMachine\My' `
                -FriendlyName 'WinRM HTTPS for Ansible' `
                -NotAfter ($now.AddYears(5))
        }

        # ------------------------------------------------------------
        # 5. Ensure listener exists and is bound to correct cert
        # ------------------------------------------------------------
        $needsListener = $true

        if ($currentThumb -and $cert.Thumbprint -eq $currentThumb) {
            $needsListener = $false
        }

        if ($needsListener) {
            Write-Host "Binding certificate to WinRM HTTPS listener..." -ForegroundColor Yellow

            try {
                winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null | Out-Null
            } catch {}

            $listenerHostname = $hostname

            winrm create winrm/config/Listener?Address=*+Transport=HTTPS `
                "@{Hostname=`"$listenerHostname`";CertificateThumbprint=`"$($cert.Thumbprint)`";Port=`"$Port`"}" |
            Out-Null

        }

        # ------------------------------------------------------------
        # 6. Safe cleanup: remove expired or truly unused WinRM certs
        # ------------------------------------------------------------
        try {
            Write-Host "Performing WinRM certificate cleanup..." -ForegroundColor Cyan

            if (-not $cert -or -not $cert.Thumbprint) {
                Write-Warning "Active WinRM certificate not identified; skipping cleanup to avoid accidental removal."
                return
            }

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
                        Write-Host "Removing stale WinRM certificate: $($_.Thumbprint)" -ForegroundColor DarkGray
                        Remove-Item $_.PSPath -Force -ErrorAction Stop
                        $removed += $_.Thumbprint
                    } catch {
                        Write-Warning "Failed to remove certificate $($_.Thumbprint): $($_.Exception.Message)"
                    }
                }

            if ($removed.Count -eq 0) {
                Write-Host "No stale or expired WinRM certificates found." -ForegroundColor Green
            } else {
                Write-Host "Removed WinRM certificates: $($removed -join ', ')" -ForegroundColor Yellow
            }

        } catch {
            Write-Warning "WinRM certificate cleanup encountered an issue and was skipped: $($_.Exception.Message)"
        }

        Write-Host "WinRM HTTPS listener and certificate are valid." -ForegroundColor Green

} else {
    Write-Host "Configuring HTTP listener on port $Port..."
    $httpListener = winrm enumerate winrm/config/listener 2>$null | Select-String "Transport = HTTP"
    if (-not $httpListener) {
        & winrm create winrm/config/Listener?Address=*+Transport=HTTP "@{Port=`"$Port`"}" | Out-Null
    } else {
        Write-Host "HTTP listener already exists."
    }

    # Add HTTP firewall rule idempotently
    Set-WinRMFirewallRule -Transport HTTP -Port $Port

}

# -------------------------------------------------------------------
# 5. Configure authentication and encryption
# -------------------------------------------------------------------
Write-Host "Configuring authentication settings..."
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true
if ($EnableCredSSP) {
    Enable-WSManCredSSP -Role Server -Force
    Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $true
} else {
    # ensure credssp is off if not requested
    try { Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $false } catch {}
}

if ($AllowUnencrypted -and -not $UseHTTPS) {
    try {
        Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
    } catch {
        Write-Warning "Could not set AllowUnencrypted via WSMan provider: $_"
        # fallback: set registry policy (already set above) — continue
    }
}

# -------------------------------------------------------------------
# 6. TrustedHosts configuration
# -------------------------------------------------------------------
if ($TrustedHosts) {
    Write-Host "Setting TrustedHosts to '$TrustedHosts'..."
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $TrustedHosts -Force
}

# -------------------------------------------------------------------
# 7. Restart WinRM and confirm
# -------------------------------------------------------------------
Restart-Service WinRM -Force

Write-Host "=== WinRM configuration complete ($(if ($UseHTTPS) {'HTTPS'} else {'HTTP'})) (Public network compatible) ===" -ForegroundColor Green
Write-Host "Port: $Port"
Write-Host "TrustedHosts: $TrustedHosts"
Write-Host "Unencrypted: $AllowUnencrypted"
Write-Host "Auth: Basic=$true, Negotiate=$true, CredSSP=$EnableCredSSP"
if ($UseHTTPS) {
    $curThumb = (winrm enumerate winrm/config/listener 2>$null | Select-String "CertificateThumbprint" | ForEach-Object { ($_ -split '=')[-1].Trim() }) | Select-Object -First 1
    Write-Host "Certificate Thumbprint: $curThumb"
}
Write-Host "`nNow you can test from Ansible:"
Write-Host "  ansible windows -i inventory.ini -m ansible.windows.win_ping" -ForegroundColor Yellow
