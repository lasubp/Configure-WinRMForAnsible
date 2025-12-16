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
    [switch]$EnableCredSSP = $false,
    [switch]$Verbose
)

if (-not $Port) {
    $Port = if ($UseHTTPS) { 5986 } else { 5985 }
}

Write-Host "=== Configuring WinRM for Ansible  (Public network compatible) ===" -ForegroundColor Cyan

# -------------------------------------------------------------------
# 0. Fix: handle systems with Public network profiles early
# -------------------------------------------------------------------
if (-not $SkipNetworkFix) {
    Write-Host "Checking network profile..." -ForegroundColor Gray
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
Write-Host "Applying WinRM policy registry keys..." -ForegroundColor Gray
$basePath = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service"
$winrsPath = "HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service\WinRS"

New-Item -Path $basePath -Force | Out-Null
New-ItemProperty -Path $basePath -Name "AllowBasic" -Value 1 -Type DWord -Force | Out-Null
New-ItemProperty -Path $basePath -Name "AllowAutoConfig" -Value 1 -Type DWord -Force | Out-Null
if ($AllowUnencrypted) {
    New-ItemProperty -Path $basePath -Name "AllowUnencryptedTraffic" -Value 1 -Type DWord -Force | Out-Null
}
New-Item -Path $winrsPath -Force | Out-Null
New-ItemProperty -Path $winrsPath -Name "AllowRemoteShellAccess" -Value 1 -Type DWord -Force | Out-Null

# -------------------------------------------------------------------
# Optimize certificate checks for offline/local networks (machine-wide)
# Avoids slow CRL/OCSP online checks for self-signed certs (reduces boot delay)
# -------------------------------------------------------------------
try {
    Write-Host "Applying machine-wide WinTrust optimization to reduce online CRL checks..." -ForegroundColor Gray
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
Write-Host "Enabling PowerShell Remoting (forcing even on Public networks)..." -ForegroundColor Gray

# Ensure WinRM waits for HTTP.sys and Cryptographic services and uses delayed auto start
Write-Host "Configuring WinRM service to depend on http/cryptsvc and to delayed-start..." -ForegroundColor Gray
sc.exe config winrm depend= http/cryptsvc | Out-Null
sc.exe config winrm start= delayed-auto | Out-Null

# Start WinRM now (service will be delayed at next boot automatically)
Start-Service -Name WinRM -ErrorAction SilentlyContinue


# -------------------------------------------------------------------
# 3. Create listener(s) (HTTPS optional) and manage HTTPS cert lifecycle
# -------------------------------------------------------------------
if ($UseHTTPS) {
    Write-Host "Configuring HTTPS listener on port $Port..." -ForegroundColor Gray

    # Determine primary IP and hostnames to include in cert
    $ipList = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '169\.254' -and $_.PrefixOrigin -ne 'WellKnown' -and $_.IPAddress -ne '127.0.0.1' }).IPAddress
    $primaryIP = $ipList | Select-Object -First 1
    if (-not $primaryIP) { $primaryIP = $env:COMPUTERNAME }

        # --- Self-healing cleanup for stale HTTPS listeners or mismatched certs ---
    Write-Host "Checking for stale HTTPS listeners or mismatched certificates..." -ForegroundColor Gray
    $hostname = $env:COMPUTERNAME

    try {
        $existingHttps = winrm enumerate winrm/config/listener 2>$null | Select-String "Transport = HTTPS"
        if ($existingHttps) {
            $stale = $false
            $listenerDump = winrm enumerate winrm/config/listener 2>$null
            foreach ($line in $listenerDump) {
                if ($line -match "Transport = HTTPS" -and ($listenerDump -match "Hostname" -and $listenerDump -notmatch $hostname -and $listenerDump -notmatch $primaryIP)) {
                    $stale = $true
                }
            }

            if ($stale) {
                Write-Host "Detected stale or mismatched HTTPS listener (hostname/IP mismatch). Removing..." -ForegroundColor Yellow
                winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null | Out-Null
            }
        }

        # Remove old WinRM HTTPS certificates that no longer match hostname/IP
        $oldCerts = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.FriendlyName -like "WinRM HTTPS for Ansible*" }
        foreach ($cert in $oldCerts) {
            if ($cert.Subject -notmatch [regex]::Escape($hostname) -and $cert.Subject -notmatch [regex]::Escape($primaryIP)) {
                Write-Host "Removing stale certificate $($cert.Subject) ($($cert.Thumbprint))..." -ForegroundColor DarkGray
                Remove-Item -Path $cert.PSPath -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Write-Warning "Self-healing cleanup encountered an issue: $_"
    }


    # Find existing HTTPS listener and bound thumbprint
    $listenerText = winrm enumerate winrm/config/listener 2>$null
    $httpsExists = $listenerText -match "Transport = HTTPS"
    $currentThumb = $null
    if ($httpsExists) {
        $thumbLine = ($listenerText | Select-String "CertificateThumbprint" -SimpleMatch) | Select-Object -First 1
        if ($thumbLine) {
            $currentThumb = ($thumbLine -split '=')[-1].Trim()
        }
    }

    $regenNeeded = $false
    $cert = $null
    if ($currentThumb) {
        $cert = Get-ChildItem -Path "Cert:\LocalMachine\My\$currentThumb" -ErrorAction SilentlyContinue
        if (-not $cert) {
            Write-Host "Bound certificate not found in store (thumb=$currentThumb) -> regenerating." -ForegroundColor Yellow
            $regenNeeded = $true
        } else {
            # Check expiry
            if ($cert.NotAfter -lt (Get-Date)) {
                Write-Host "Bound certificate is expired (NotAfter: $($cert.NotAfter)). Regeneration required." -ForegroundColor Yellow
                $regenNeeded = $true
            } else {
                # Check if cert subject or SAN matches primary IP or computer name
                $subjectMatches = $false
                if ($cert.Subject -match [regex]::Escape($env:COMPUTERNAME)) { $subjectMatches = $true }
                if ($primaryIP -and ($cert.Subject -match [regex]::Escape($primaryIP))) { $subjectMatches = $true }
                # also check SANs (if available)
                try {
                    $san = ($cert.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" } ).Format($false)
                    if ($san -and ($san -match [regex]::Escape($primaryIP) -or $san -match [regex]::Escape($env:COMPUTERNAME))) { $subjectMatches = $true }
                } catch { }

                if (-not $subjectMatches) {
                    Write-Host "Certificate CN/SAN does not match hostname or IP. Regeneration required." -ForegroundColor Yellow
                    $regenNeeded = $true
                } else {
                    Write-Host "Existing HTTPS certificate is valid and matches host." -ForegroundColor Green
                }
            }
        }
    } else {
        Write-Host "No HTTPS listener or bound certificate found -> creating new certificate and listener." -ForegroundColor Yellow
        $regenNeeded = $true
    }

    if ($regenNeeded) {
        Write-Host "Creating new self-signed certificate for WinRM HTTPS (CN/SAN: $primaryIP, $($env:COMPUTERNAME))..." -ForegroundColor Yellow
        # Create cert including primaryIP and computername as DNS names (works for many environments)
        # Note: if you need IP to be in SAN explicitly in your environment, replace or extend this creation with advanced TextExtension usage.
        $dnsNames = @()
        if ($primaryIP) { $dnsNames += $primaryIP }
        $dnsNames += $env:COMPUTERNAME
        $cert = New-SelfSignedCertificate -DnsName $dnsNames -CertStoreLocation "Cert:\LocalMachine\My" -FriendlyName "WinRM HTTPS for Ansible" -NotAfter (Get-Date).AddYears(5)

        # Remove any existing HTTPS listeners (safe)
        try { winrm delete winrm/config/Listener?Address=*+Transport=HTTPS 2>$null } catch {}

        # Create the HTTPS listener bound to the certificate thumbprint and port
        $thumb = $cert.Thumbprint
        Write-Host "Binding new certificate (thumb: $thumb) to WinRM HTTPS listener..." -ForegroundColor Gray
        & winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$primaryIP`"; CertificateThumbprint=`"$thumb`";Port=`"$Port`"}" | Out-Null
    } else {
        Write-Host "Ensuring HTTPS listener exists and is bound to the certificate..." -ForegroundColor Gray
        if (-not $httpsExists) {
            # create listener and bind current cert if available, else regenerate
            if ($cert) {
                $thumb = $cert.Thumbprint
                & winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$primaryIP`"; CertificateThumbprint=`"$thumb`";Port=`"$Port`"}" | Out-Null
            } else {
                Write-Host "No cert available to bind -> creating new cert..." -ForegroundColor Yellow
                $cert = New-SelfSignedCertificate -DnsName @($primaryIP,$env:COMPUTERNAME) -CertStoreLocation "Cert:\LocalMachine\My" -FriendlyName "WinRM HTTPS for Ansible" -NotAfter (Get-Date).AddYears(5)
                $thumb = $cert.Thumbprint
                & winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$primaryIP`"; CertificateThumbprint=`"$thumb`";Port=`"$Port`"}" | Out-Null
            }
        }
    }

    # # Add HTTPS firewall rule idempotently
    # if (-not (Get-NetFirewallRule -DisplayName $"WinRM HTTPS ($Port)" -ErrorAction SilentlyContinue)) {
    #     New-NetFirewallRule -DisplayName "WinRM HTTPS ($Port)" -Name "WinRM_HTTPS" -Protocol TCP -LocalPort $Port -Direction Inbound -Action Allow -Profile Any | Out-Null
    # } else {
    #     New-NetFirewallRule -DisplayName "WinRM HTTP ($Port)" -Name "WinRM_HTTP" -Protocol TCP -LocalPort $Port -Direction Inbound -Action Allow -Profile Any | Out-Null
    # }

    # -------------------------------------------------------------------
    # Safe cleanup: remove expired or unbound WinRM certificates
    # -------------------------------------------------------------------
    try {
        Write-Host "Performing WinRM certificate store cleanup..." -ForegroundColor Gray
        $boundThumbs = (winrm enumerate winrm/config/listener 2>$null |
            Select-String "CertificateThumbprint" |
            ForEach-Object { ($_ -split '=')[-1].Trim() }) | Where-Object { $_ }
        
        $removed = @()
            
        Get-ChildItem -Path Cert:\LocalMachine\My |
            Where-Object {
                $_.FriendlyName -eq "WinRM HTTPS for Ansible" -and (
                    ($_.Thumbprint -notin $boundThumbs) -or
                    ($_.NotAfter -lt (Get-Date))
                )
            } |
            ForEach-Object {
                Write-Host "Removing stale or expired certificate: $($_.Thumbprint)" -ForegroundColor DarkGray
                Remove-Item -Path $_.PSPath -Force -ErrorAction SilentlyContinue
                $removed += $_.Thumbprint
            }
        if ($removed.Count -eq 0) {
            Write-Host "No stale or expired certificates found for cleanup." -ForegroundColor Gray
        } else {
            Write-Host "Removed certificates: $($removed -join ', ')" -ForegroundColor Gray
        }   
    } catch {
        Write-Warning "Certificate cleanup encountered an issue: $_"
    }


} else {
    Write-Host "Configuring HTTP listener on port $Port..." -ForegroundColor Gray
    $httpListener = winrm enumerate winrm/config/listener 2>$null | Select-String "Transport = HTTP"
    if (-not $httpListener) {
        & winrm create winrm/config/Listener?Address=*+Transport=HTTP "@{Port=`"$Port`"}" | Out-Null
    } else {
        Write-Host "HTTP listener already exists." -ForegroundColor Gray
    }

    # Add HTTP firewall rule idempotently
    $fwName = "WinRM HTTP (5985)"
    if (-not (Get-NetFirewallRule -DisplayName $fwName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $fwName -Name "WinRM_HTTP" -Protocol TCP -LocalPort $Port -Direction Inbound -Action Allow -Profile Any | Out-Null
    } else {
        Write-Host "Firewall rule '$fwName' already exists. Skipping creation." -ForegroundColor Gray
    }
}

# -------------------------------------------------------------------
# 4. Firewall rules for all profiles (Domain, Private, Public) - ensure rule exists and applies to all profiles
# -------------------------------------------------------------------
Write-Host "Ensuring firewall rule applies to all profiles..." -ForegroundColor Gray
$ruleName = if ($UseHTTPS) { "WinRM HTTPS Inbound" } else { "WinRM HTTP Inbound" }
$portNum = $Port

$existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
if ($existing) {
    # ensure the rule has the expected port and profiles
    Get-NetFirewallRule -DisplayName $ruleName |
        Set-NetFirewallRule -Profile Domain,Private,Public -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
        Out-Null
    # try to set proper port via associated NetFirewallPortFilter (skip if complex)
} else {
    New-NetFirewallRule `
    -Name $ruleName `
    -DisplayName $ruleName `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort $portNum `
    -Action Allow `
    -Profile Domain,Private,Public `
    -Description "Allow WinRM traffic for Ansible on all network profiles" |
    Out-Null
}

# -------------------------------------------------------------------
# 5. Configure authentication and encryption
# -------------------------------------------------------------------
Write-Host "Configuring authentication settings..." -ForegroundColor Gray
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
    Write-Host "Setting TrustedHosts to '$TrustedHosts'..." -ForegroundColor Gray
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $TrustedHosts -Force
}

# -------------------------------------------------------------------
# 7. Restart WinRM and confirm
# -------------------------------------------------------------------
Restart-Service WinRM -Force

Write-Host "=== WinRM configuration complete ($(if ($UseHTTPS) {'HTTPS'} else {'HTTP'})) (Public network compatible) ===" -ForegroundColor Green
Write-Host "Port: $portNum"
Write-Host "TrustedHosts: $TrustedHosts"
Write-Host "Unencrypted: $AllowUnencrypted"
Write-Host "Auth: Basic=$true, Negotiate=$true, CredSSP=$EnableCredSSP"
if ($UseHTTPS) {
    $curThumb = (winrm enumerate winrm/config/listener 2>$null | Select-String "CertificateThumbprint" | ForEach-Object { ($_ -split '=')[-1].Trim() }) | Select-Object -First 1
    Write-Host "Certificate Thumbprint: $curThumb"
}
Write-Host "`nNow you can test from Ansible:"
Write-Host "  ansible windows -i inventory.ini -m ansible.windows.win_ping" -ForegroundColor Yellow
