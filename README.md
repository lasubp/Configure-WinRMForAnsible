# Configure-WinRMForAnsible

PowerShell scripts to configure Windows hosts for Ansible over WinRM (HTTP or HTTPS) or OpenSSH, plus a bootstrapper that can elevate and set up a SYSTEM self-heal task.

## Scripts

- `Configure-WinRMForAnsible.ps1`: main configuration script (requires Admin).
- `Configure-SSHForAnsible.ps1`: OpenSSH configuration script (requires Admin).
- `bootstrap.ps1`: helper that downloads the latest main script, optionally elevates, and creates a SYSTEM scheduled task for startup self-heal.

## Requirements

- Windows 10 / 11 / Server 2016+
- PowerShell 5.1+
- Must run main script as Administrator
- OpenSSH Server capability (installed automatically by `Configure-SSHForAnsible.ps1`)

## What the main script does

- Applies WinRM policy registry keys
- Enables and starts WinRM service (delayed auto)
- Creates HTTP or HTTPS listeners (self-signed cert for HTTPS if needed)
- Adds firewall rules for all network profiles
- Configures authentication (Basic + Negotiate; optional CredSSP)
- Configures TrustedHosts (idempotent)
- Optional local service user creation and hardening
- Optional lock-screen UX preservation for single-user desktops
- Logs to file and optionally Event Log

## Usage (main script)

### Basic (HTTP)

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-WinRMForAnsible.ps1
```

### HTTPS (self-signed)

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-WinRMForAnsible.ps1 -UseHTTPS -TrustedHosts "*"
```

### Custom TrustedHosts

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-WinRMForAnsible.ps1 -TrustedHosts "192.168.*,10.0.*"
```

### Create a local service user

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-WinRMForAnsible.ps1 `
  -NewUser -ServiceUserName ansible_svc -ServiceUserPassFile C:\Temp\ansible.pass
```

## Usage (OpenSSH)

### Basic (port 22)

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-SSHForAnsible.ps1
```

### Public-key only for a service user

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-SSHForAnsible.ps1 `
  -NewUser -ServiceUserName ansible_ssh -UsePublicKeyOnly -PublicKeyFile C:\Temp\ansible.pub
```

### Custom port and allowed users

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-SSHForAnsible.ps1 `
  -Port 2222 -AllowUsers ansible_ssh,admin1
```

## Usage (bootstrap)

`bootstrap.ps1` is designed to be run from a user session. It will:

- If not admin: create a Startup launcher and prompt for UAC elevation.
- If admin: download the main script and create a SYSTEM scheduled task to run it at startup.
- If SYSTEM: download and run the main script silently.

Example (pass through main script args):

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\bootstrap.ps1 -UseHTTPS -TrustedHosts "*"
```

## Logging

### Main script

- Default log file (elevated runs only): `C:\ProgramData\Configure-WinRMForAnsible\Configure-WinRMForAnsible.log`
- Non-elevated runs do not write the default log unless you explicitly pass `-LogPath`.
- Console output is user-friendly (no timestamps); log file keeps timestamps.
- Event Log is enabled by default and can be disabled.

Options:

- `-LogPath` to log to a custom path (any user-writable location).
- `-LogFormat text|json` (default: `text`).
- `-DisableEventLog` to skip Event Viewer logging.
- `-FriendlyErrors:$false` to use PowerShell error records instead of friendly console messages.

### OpenSSH script

- Default log file (elevated runs only): `C:\ProgramData\Configure-SSHForAnsible\Configure-SSHForAnsible.log`
- Same logging options as the main script (`-LogPath`, `-LogFormat`, `-DisableEventLog`, `-FriendlyErrors`).

### Bootstrap

- Always logs to a single file, even on first non-elevated run:
  `C:\Users\Public\Documents\Configure-WinRMForAnsible\bootstrap.log`
- Sensitive args are sanitized in the log (`-ServiceUserPass` is masked).

## Parameters (main script)

| Parameter | Description | Default |
| --- | --- | --- |
| `-UseHTTPS` | Enable HTTPS listener and certificate management | Disabled |
| `-Port` | Custom port (5985 HTTP / 5986 HTTPS) | Auto |
| `-TrustedHosts` | TrustedHosts value | `*` |
| `-AllowUnencrypted` | Allow unencrypted traffic (HTTP only) | `$true` |
| `-SkipNetworkFix` | Skip Public -> Private network change | `$false` |
| `-EnableCredSSP` | Enable CredSSP authentication | `$false` |
| `-NewUser` | Create a local service user | `$false` |
| `-ServiceUserName` | Service user name | `ansible_svc` |
| `-ServiceUserPass` | Service user password (unsafe on CLI) | — |
| `-ServiceUserPassFile` | File containing service user password | — |
| `-LogPath` | Custom log file path | — |
| `-LogFormat` | `text` or `json` | `text` |
| `-DisableEventLog` | Disable Event Viewer logging | `$false` |
| `-FriendlyErrors` | Friendly console errors | `$true` |

## Parameters (OpenSSH script)

| Parameter | Description | Default |
| --- | --- | --- |
| `-Port` | SSH port | `22` |
| `-UsePublicKeyOnly` | Disable password auth | `$false` |
| `-AllowPasswordAuth` | Allow password auth | `$true` |
| `-AllowSftp` | Enable SFTP subsystem | `$true` |
| `-AllowUsers` | Restrict allowed users | — |
| `-PublicKeyFile` | Public key to add to `authorized_keys` | — |
| `-AuthorizedKeysPath` | Override `authorized_keys` path | — |
| `-DefaultShell` | Default SSH shell | PowerShell 5.1 |
| `-NewUser` | Create a local service user | `$false` |
| `-ServiceUserName` | Service user name | `ansible_ssh` |
| `-ServiceUserPass` | Service user password (unsafe on CLI) | — |
| `-ServiceUserPassFile` | File containing service user password | — |
| `-LogPath` | Custom log file path | — |
| `-LogFormat` | `text` or `json` | `text` |
| `-DisableEventLog` | Disable Event Viewer logging | `$false` |
| `-FriendlyErrors` | Friendly console errors | `$true` |

## Example Ansible inventory (HTTPS)

```yaml
all:
  children:
    windows:
      hosts:
        winhost:
          ansible_host: 192.168.9.120
          ansible_user: admin
          ansible_password: "StrongPass123"
          ansible_connection: winrm
          ansible_port: 5986
          ansible_winrm_transport: basic
          ansible_winrm_server_cert_validation: ignore
```

Test:

```bash
ansible -i inventory.yml windows -m win_ping
```

## Troubleshooting

```powershell
winrm enumerate winrm/config/listener
Test-WsMan localhost
Get-NetFirewallRule | Where-Object DisplayName -like "*WinRM*"
Restart-Service WinRM -Force
winrm get winrm/config/service
winrm get winrm/config/service/auth
```

## Notes and security

- For production, use CA-issued certificates and restrict TrustedHosts.
- Avoid `-ServiceUserPass` on the command line; prefer `-ServiceUserPassFile`.
- `bootstrap.ps1` downloads the main script from a URL; review and pin it for production use.

## License

MIT License.
