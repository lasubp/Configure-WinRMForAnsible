<#
.SYNOPSIS
  Fully configures a Windows host for Ansible remoting via WinRM,
  even when network profile is set to Public.

.DESCRIPTION
  - Applies persistent WinRM policy registry keys
  - Enables and starts WinRM service
  - Creates listeners (HTTP default, HTTPS optional)
  - Adds firewall rules for *all* network profiles
  - Configures authentication and TrustedHosts
  - No user interaction required
#>

param(
    [switch]$UseHTTPS,
    [string]$TrustedHosts = "*",
    [int]$Port,
    [switch]$AllowUnencrypted = $true,
    [switch]$SkipNetworkFix = $false,
    [switch]$Verbose
)

if (-not $Port) {
    $Port = if ($UseHTTPS) { 5986 } else { 5985 }
}

Write-Host "=== Configuring WinRM for Ansible  (Public network compatible) ===" -ForegroundColor Cyan

# -------------------------------------------------------------------
# 1. Apply persistent WinRM policy keys
# -------------------------------------------------------------------
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
# 2. Enable PS Remoting without blocking on Public network
# -------------------------------------------------------------------
Write-Host "Enabling PowerShell Remoting (forcing even on Public networks)..."
Set-Service -Name WinRM -StartupType Automatic
Start-Service -Name WinRM

# Skip 'Enable-PSRemoting' restrictions by manually creating listeners

if ($UseHTTPS) {
    Write-Host "Configuring HTTPS listener on port $Port..."

    $ipList = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '169\.254' -and $_.PrefixOrigin -ne 'WellKnown' }).IPAddress
    $primaryIP = $ipList | Select-Object -First 1

    # Find existing suitable certificate
    $existingCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {
        $_.Subject -match $env:COMPUTERNAME -or $_.Subject -match $primaryIP
    } | Select-Object -First 1

    if (-not $existingCert) {
        Write-Host "Creating new self-signed certificate for CN=$primaryIP..."
        $existingCert = New-SelfSignedCertificate -DnsName $primaryIP,$env:COMPUTERNAME `
            -CertStoreLocation "Cert:\LocalMachine\My" `
            -FriendlyName "WinRM HTTPS for Ansible"
    }

    $thumb = $existingCert.Thumbprint
    Write-Host "Binding certificate thumbprint $thumb to WinRM HTTPS listener..."

    # Remove old listeners (if any)
    $httpsListeners = winrm enumerate winrm/config/listener | findstr /C:"Transport=HTTPS"
    if ($httpsListeners) {
        Write-Host "Removing existing HTTPS listener..."
        & winrm delete winrm/config/Listener?Address=*+Transport=HTTPS | Out-Null
    }

    # Create HTTPS listener
    & winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$primaryIP`"; CertificateThumbprint=`"$thumb`"}" | Out-Null

    Write-Host "Adding HTTPS firewall rules (Public-safe)..."
    if (-not (Get-NetFirewallRule -DisplayName "WinRM HTTPS (5986)" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "WinRM HTTPS (5986)" -Name "WinRM_HTTPS" `
            -Protocol TCP -LocalPort 5986 -Direction Inbound -Action Allow -Profile Any | Out-Null
    }

} else {
    Write-Host "Configuring HTTP listener on port $Port..."
    $httpListener = winrm enumerate winrm/config/listener | findstr /C:"Transport=HTTP"
    if (-not $httpListener) {
        & winrm create winrm/config/Listener?Address=*+Transport=HTTP | Out-Null
    } else {
        Write-Host "HTTP listener already exists."
    }

    Write-Host "Adding HTTP firewall rules (Public-safe)..."
    if (-not (Get-NetFirewallRule -DisplayName "WinRM HTTP (5985)" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "WinRM HTTP (5985)" -Name "WinRM_HTTP" `
            -Protocol TCP -LocalPort 5985 -Direction Inbound -Action Allow -Profile Any | Out-Null
    }
}


# -------------------------------------------------------------------
# 3. Firewall rules for all profiles (Domain, Private, Public)
# -------------------------------------------------------------------
Write-Host "Adding firewall rules for all profiles (Public-safe)..."

$ruleName = if ($UseHTTPS) { "WinRM HTTPS Inbound" } else { "WinRM HTTP Inbound" }
$port = if ($UseHTTPS) { 5986 } else { 5985 }

# Remove any existing conflicting rule
Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

# Create new rule that applies to ALL profiles
New-NetFirewallRule -Name $ruleName `
    -DisplayName $ruleName `
    -Direction Inbound -Protocol TCP -LocalPort $port `
    -Action Allow -Profile Domain,Private,Public `
    -Description "Allow WinRM traffic for Ansible on all network profiles" | Out-Null

# -------------------------------------------------------------------
# Fix: handle systems with Public network profiles
# -------------------------------------------------------------------
if (-not $SkipNetworkFix) {
    Write-Host "Checking network profile..."
    $publicNetworks = Get-NetConnectionProfile | Where-Object {$_.NetworkCategory -eq "Public"}
    if ($publicNetworks) {
        Write-Host "Public network detected. Switching to Private to allow WinRM configuration..."
        $publicNetworks | Set-NetConnectionProfile -NetworkCategory Private
        Start-Sleep 2
    }
}



# -------------------------------------------------------------------
# 4. Configure authentication and encryption
# -------------------------------------------------------------------
Write-Host "Configuring authentication settings..."
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true
if ($EnableCredSSP) {
    Enable-WSManCredSSP -Role Server -Force
    Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $true
}
if ($AllowUnencrypted) {
    Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
}

# -------------------------------------------------------------------
# 5. TrustedHosts configuration
# -------------------------------------------------------------------
if ($TrustedHosts) {
    Write-Host "Setting TrustedHosts to '$TrustedHosts'..."
    Set-Item WSMan:\localhost\Client\TrustedHosts -Value $TrustedHosts -Force
}

# -------------------------------------------------------------------
# 6. Restart WinRM and confirm
# -------------------------------------------------------------------
Restart-Service WinRM

Write-Host "=== WinRM configuration complete ($(if ($UseHTTPS) {'HTTPS'} else {'HTTP'})) (Public network compatible) ===" -ForegroundColor Green
Write-Host "Port: $port"
Write-Host "TrustedHosts: $TrustedHosts"
Write-Host "Unencrypted: $AllowUnencrypted"
Write-Host "Auth: Basic=$true, Negotiate=$true, CredSSP=False"
Write-Host "`nNow you can test from Ansible:"
Write-Host "  ansible windows -i inventory.ini -m ansible.windows.win_ping" -ForegroundColor Yellow
