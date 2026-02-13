<#
.SYNOPSIS
  One-command tester for Configure-SSHForAnsible.ps1 and Configure-WinRMForAnsible.ps1.

.DESCRIPTION
  - Creates temp password and SSH key files
  - Runs SSH and/or WinRM configuration scripts with full test argument sets
  - Prints basic service/connectivity checks

  Requires an elevated PowerShell session.
#>

[CmdletBinding()]
param(
    [ValidateSet('SSH','WinRM','Both')]
    [string]$Mode = 'SSH',

    [string]$SSHScriptPath,
    [string]$WinRMScriptPath,

    [string]$ServiceUserName = 'ansible_agent',
    [string]$ServiceUserPassword = 'p@ssw0rd!',

    [int]$SSHPort = 2222,
    [switch]$UseHTTPSForWinRM
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([string]$Message)
    Write-Host "==> $Message" -ForegroundColor Cyan
}

function Resolve-ScriptPath {
    param(
        [Parameter(Mandatory)][string]$ProvidedPath,
        [Parameter(Mandatory)][string]$LocalFileName,
        [Parameter(Mandatory)][string]$FallbackPath
    )

    if ($ProvidedPath) {
        if (Test-Path $ProvidedPath) { return $ProvidedPath }
        throw "Script path not found: $ProvidedPath"
    }

    $local = Join-Path $PSScriptRoot $LocalFileName
    if (Test-Path $local) { return $local }
    if (Test-Path $FallbackPath) { return $FallbackPath }

    throw "Could not find $LocalFileName in '$PSScriptRoot' or '$FallbackPath'."
}

function New-TestPasswordFile {
    param([Parameter(Mandatory)][string]$Password)

    $path = Join-Path $env:TEMP 'ansible_agent.pass'
    $Password | Set-Content -Path $path -Encoding Ascii
    return $path
}

function New-TestPublicKeyFile {
    $keyBase = Join-Path $env:TEMP 'ansible_agent_key'
    $pubPath = "$keyBase.pub"
    if (Test-Path $pubPath) {
        return $pubPath
    }

    $keygen = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
    if (-not (Test-Path $keygen)) {
        throw "ssh-keygen not found at '$keygen'."
    }

    # Use cmd /c to preserve empty passphrase argument reliably on PowerShell 5.1.
    cmd /c "`"$keygen`" -t ed25519 -N `"`" -f `"$keyBase`""
    if (-not (Test-Path $pubPath)) {
        throw "Public key was not created: $pubPath"
    }

    return $pubPath
}

function Invoke-SSHTest {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$ServiceUser,
        [Parameter(Mandatory)][string]$PassFile,
        [Parameter(Mandatory)][string]$PubKeyFile,
        [Parameter(Mandatory)][int]$Port
    )

    Write-Step "Running SSH config test"
    $args = @(
        '-ExecutionPolicy','Bypass',
        '-File', $ScriptPath,
        '-Port', $Port,
        '-UsePublicKeyOnly',
        '-NoPasswordAuth',
        '-NoSftp',
        '-AllowUsers', "$ServiceUser,Administrator",
        '-PublicKeyFile', $PubKeyFile,
        '-AuthorizedKeysPath', 'C:\ProgramData\ssh\administrators_authorized_keys',
        '-DefaultShell', "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe",
        '-LogPath', 'C:\ProgramData\Configure-SSHForAnsible\ssh-test.log',
        '-LogFormat', 'json',
        '-DisableEventLog',
        '-FullErrors',
        '-NewUser',
        '-ServiceUserName', $ServiceUser,
        '-ServiceUserPassFile', $PassFile
    )

    & powershell.exe @args
    if ($LASTEXITCODE -ne 0) {
        throw "SSH test script failed with exit code $LASTEXITCODE."
    }

    Write-Step "SSH verification"
    Get-Service sshd | Select-Object Name, Status, StartType | Format-Table -AutoSize
    Test-NetConnection -ComputerName localhost -Port $Port | Select-Object ComputerName, RemotePort, TcpTestSucceeded | Format-Table -AutoSize
}

function Invoke-WinRMTest {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][string]$ServiceUser,
        [Parameter(Mandatory)][string]$PassFile,
        [switch]$UseHTTPS
    )

    Write-Step "Running WinRM config test"
    $port = if ($UseHTTPS) { 5986 } else { 5985 }

    $args = @(
        '-ExecutionPolicy','Bypass',
        '-File', $ScriptPath,
        '-TrustedHosts', '*',
        '-Port', $port,
        '-SkipNetworkFix',
        '-EnableCredSSP',
        '-LogPath', 'C:\ProgramData\Configure-WinRMForAnsible\winrm-test.log',
        '-LogFormat', 'json',
        '-DisableEventLog',
        '-FullErrors',
        '-NewUser',
        '-ServiceUserName', $ServiceUser,
        '-ServiceUserPassFile', $PassFile
    )

    if ($UseHTTPS) {
        $args += '-UseHTTPS'
    }
    else {
        $args += '-EncryptedOnly'
    }

    & powershell.exe @args
    if ($LASTEXITCODE -ne 0) {
        throw "WinRM test script failed with exit code $LASTEXITCODE."
    }

    Write-Step "WinRM verification"
    Get-Service WinRM | Select-Object Name, Status, StartType | Format-Table -AutoSize
    Test-WsMan localhost | Out-Host
}

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script in an elevated PowerShell session."
}

$resolvedSSH = Resolve-ScriptPath -ProvidedPath $SSHScriptPath -LocalFileName 'Configure-SSHForAnsible.ps1' -FallbackPath 'C:\Users\User\Configure-SSHForAnsible.ps1'
$resolvedWinRM = Resolve-ScriptPath -ProvidedPath $WinRMScriptPath -LocalFileName 'Configure-WinRMForAnsible.ps1' -FallbackPath 'C:\Users\User\Configure-WinRMForAnsible.ps1'

Write-Step "Preparing temporary test files"
$passFile = New-TestPasswordFile -Password $ServiceUserPassword
$pubKeyFile = New-TestPublicKeyFile

if ($Mode -in @('SSH','Both')) {
    Invoke-SSHTest -ScriptPath $resolvedSSH -ServiceUser $ServiceUserName -PassFile $passFile -PubKeyFile $pubKeyFile -Port $SSHPort
}

if ($Mode -in @('WinRM','Both')) {
    Invoke-WinRMTest -ScriptPath $resolvedWinRM -ServiceUser $ServiceUserName -PassFile $passFile -UseHTTPS:$UseHTTPSForWinRM
}

Write-Step "Completed"
