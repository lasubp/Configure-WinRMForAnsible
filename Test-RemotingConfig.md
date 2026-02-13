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
