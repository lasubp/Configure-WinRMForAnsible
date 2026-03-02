# Test-RemotingConfig Usage

## Purpose

`Test-RemotingConfig.ps1` runs end-to-end test setup for:

- `Configure-SSHForAnsible.ps1`
- `Configure-WinRMForAnsible.ps1`

It creates temporary test password/key files, executes the selected config script(s), and prints basic verification checks.

## Prerequisites

- Run in an **elevated** PowerShell session (Run as Administrator).
- Scripts should exist in either:
  - same folder as `Test-RemotingConfig.ps1`, or
  - `C:\Users\User\`

## Quick Start

SSH only:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\Users\User\Test-RemotingConfig.ps1 -Mode SSH
```

WinRM only:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\Users\User\Test-RemotingConfig.ps1 -Mode WinRM
```

Both:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\Users\User\Test-RemotingConfig.ps1 -Mode Both
```

Both with WinRM HTTPS:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\Users\User\Test-RemotingConfig.ps1 -Mode Both -UseHTTPSForWinRM
```

## Common Overrides

Custom user/password:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\Users\User\Test-RemotingConfig.ps1 `
  -Mode Both `
  -ServiceUserName ansible_agent `
  -ServiceUserPassword 'p@ssw0rd!'
```

Custom SSH port:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\Users\User\Test-RemotingConfig.ps1 `
  -Mode SSH `
  -SSHPort 2222
```

Custom script paths:

```powershell
powershell.exe -ExecutionPolicy Bypass -File C:\Users\User\Test-RemotingConfig.ps1 `
  -Mode Both `
  -SSHScriptPath C:\Users\User\Configure-SSHForAnsible.ps1 `
  -WinRMScriptPath C:\Users\User\Configure-WinRMForAnsible.ps1
```

## Parameters

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `-Mode` | `SSH` / `WinRM` / `Both` | `SSH` | Select which config flow(s) to test |
| `-SSHScriptPath` | string | auto-discovery | Explicit path to SSH config script |
| `-WinRMScriptPath` | string | auto-discovery | Explicit path to WinRM config script |
| `-ServiceUserName` | string | `ansible_agent` | Test service account name |
| `-ServiceUserPassword` | string | `p@ssw0rd!` | Value written to temp password file |
| `-SSHPort` | int | `2222` | SSH port used for test run |
| `-UseHTTPSForWinRM` | switch | off | Use HTTPS mode for WinRM test |

## What It Verifies

- SSH mode:
  - `sshd` service status/startup
  - local TCP connectivity to selected SSH port
- WinRM mode:
  - `WinRM` service status/startup
  - `Test-WsMan localhost`

## Manual Full Test (Files in C:\Users\User)

Run all commands in an elevated PowerShell session.

### 1) Prepare test password file and SSH key

```powershell
$PassFile = "$env:TEMP\ansible_agent.pass"
'p@ssw0rd!' | Set-Content -Path $PassFile -Encoding Ascii

$KeyFileBase = Join-Path $env:TEMP 'ansible_agent_key'
$PubKeyFile  = "$KeyFileBase.pub"
if (-not (Test-Path $PubKeyFile)) {
  cmd /c "`"$env:SystemRoot\System32\OpenSSH\ssh-keygen.exe`" -t ed25519 -N `"`" -f `"$KeyFileBase`""
}
```

### 2) SSH test with strict flags

```powershell
powershell.exe -ExecutionPolicy Bypass -File 'C:\Users\User\Configure-SSHForAnsible.ps1' `
  -Port 2222 `
  -UsePublicKeyOnly `
  -NoPasswordAuth `
  -NoSftp `
  -AllowUsers ansible_agent,Administrator `
  -PublicKeyFile $PubKeyFile `
  -AuthorizedKeysPath 'C:\ProgramData\ssh\administrators_authorized_keys' `
  -DefaultShell "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -LogPath 'C:\ProgramData\Configure-SSHForAnsible\ssh-test-json.log' `
  -LogFormat json `
  -DisableEventLog `
  -FullErrors `
  -NewUser `
  -ServiceUserName ansible_agent `
  -ServiceUserPassFile $PassFile
```

### 3) SSH test with defaults (password + SFTP enabled)

```powershell
powershell.exe -ExecutionPolicy Bypass -File 'C:\Users\User\Configure-SSHForAnsible.ps1' `
  -Port 22 `
  -AllowUsers ansible_agent `
  -PublicKeyFile $PubKeyFile `
  -DefaultShell "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
  -LogPath 'C:\ProgramData\Configure-SSHForAnsible\ssh-test-text.log' `
  -LogFormat text `
  -NewUser `
  -ServiceUserName ansible_agent `
  -ServiceUserPass 'p@ssw0rd!'
```

### 4) WinRM HTTP test

```powershell
powershell.exe -ExecutionPolicy Bypass -File 'C:\Users\User\Configure-WinRMForAnsible.ps1' `
  -TrustedHosts '*' `
  -Port 5985 `
  -SkipNetworkFix `
  -EnableCredSSP `
  -LogPath 'C:\ProgramData\Configure-WinRMForAnsible\winrm-http-json.log' `
  -LogFormat json `
  -DisableEventLog `
  -FullErrors `
  -NewUser `
  -ServiceUserName ansible_agent `
  -ServiceUserPassFile $PassFile
```

### 5) WinRM HTTP with encrypted-only mode

```powershell
powershell.exe -ExecutionPolicy Bypass -File 'C:\Users\User\Configure-WinRMForAnsible.ps1' `
  -TrustedHosts '*' `
  -Port 5985 `
  -EncryptedOnly `
  -SkipNetworkFix `
  -LogPath 'C:\ProgramData\Configure-WinRMForAnsible\winrm-http-encryptedonly.log' `
  -LogFormat text `
  -FullErrors `
  -NewUser `
  -ServiceUserName ansible_agent `
  -ServiceUserPassFile $PassFile
```

### 6) WinRM HTTPS test

```powershell
powershell.exe -ExecutionPolicy Bypass -File 'C:\Users\User\Configure-WinRMForAnsible.ps1' `
  -UseHTTPS `
  -TrustedHosts '*' `
  -Port 5986 `
  -EnableCredSSP `
  -LogPath 'C:\ProgramData\Configure-WinRMForAnsible\winrm-https-json.log' `
  -LogFormat json `
  -DisableEventLog `
  -FullErrors `
  -NewUser `
  -ServiceUserName ansible_agent `
  -ServiceUserPassFile $PassFile
```

### 7) Verify services and connectivity

```powershell
Get-Service sshd,WinRM | Select Name,Status,StartType
Test-NetConnection localhost -Port 22   | Select ComputerName,RemotePort,TcpTestSucceeded
Test-NetConnection localhost -Port 2222 | Select ComputerName,RemotePort,TcpTestSucceeded
winrm enumerate winrm/config/listener
Test-WsMan localhost
```

### 8) Optional: recent related errors

```powershell
Get-WinEvent -LogName System -MaxEvents 200 |
  Where-Object { $_.Id -in 7000,7009,7031,7034,7041 -and $_.Message -match 'sshd|WinRM' } |
  Select TimeCreated,Id,Message
```
