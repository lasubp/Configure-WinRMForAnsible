# Configure-WinRMForAnsible.ps1

## Automated WinRM setup for Windows clients managed by Ansible (HTTP & HTTPS)

This PowerShell script automatically configures Windows systems for remote management with **Ansible over WinRM**, supporting both **HTTP (port 5985)** and **HTTPS (port 5986)**.
It runs fully unattended, fixes Public network restrictions, and can be safely re-run anytime.

---

## 🧩 Features

* Enables PowerShell Remoting and the WinRM service
* Works on **Public**, **Private**, and **Domain** networks
* Supports **HTTP** (default) and **HTTPS** with self-signed certificates
* Adds firewall rules for all network profiles
* Enables **Basic** and **Negotiate** authentication
* Optionally allows unencrypted traffic (useful for testing or lab setups)
* Automatically configures `TrustedHosts`
* Idempotent — can be re-run safely without side effects

---

## ⚙️ Requirements

* Run as **Administrator**
* Windows 10 / 11 / Server 2016 or later
* PowerShell 5.1+
* Ansible controller with the `pywinrm` Python module installed

---

## 🚀 Usage

### Basic (HTTP)

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-WinRMForAnsible.ps1
```

### With custom TrustedHosts

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-WinRMForAnsible.ps1 -TrustedHosts "192.168.*,10.0.*"
```

### Enable HTTPS (port 5986)

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-WinRMForAnsible.ps1 -UseHTTPS -TrustedHosts "*"
```

This creates a **self-signed certificate** (if none exists) and binds it to the WinRM HTTPS listener.
The certificate is automatically stored in the **LocalMachine\My** store.

---

## 🧰 Available Parameters

| Parameter           | Description                                                              | Default  |
| ------------------- | ------------------------------------------------------------------------ | -------- |
| `-UseHTTPS`         | Enables and configures HTTPS listener on port **5986**                   | Disabled |
| `-Port`             | Port to use (5985 for HTTP, 5986 for HTTPS)                              | Auto     |
| `-TrustedHosts`     | Comma-separated list of allowed hosts (e.g. `"*"`, `"192.168.*,10.0.*"`) | `*`      |
| `-AllowUnencrypted` | Allow unencrypted communication (HTTP only)                              | `$true`  |
| `-SkipNetworkFix`   | Skip automatic conversion of Public → Private networks                   | `$false` |
| `-Verbose`          | Show detailed output                                                     | —        |

**Example:**

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-WinRMForAnsible.ps1 -UseHTTPS -TrustedHosts "192.168.9.*,10.10.*" -Verbose
```

---

## 🧩 Example Ansible Inventory (HTTPS)

```yaml
all:
  children:
    windows:
      hosts:
        win11-secure:
          ansible_host: 192.168.9.120
          ansible_user: admin
          ansible_password: "StrongPass123"
          ansible_connection: winrm
          ansible_port: 5986
          ansible_winrm_transport: basic
          ansible_winrm_server_cert_validation: ignore
```

**Test connection:**

```bash
ansible -i inventory.yml windows -m win_ping
```

---

## 🧼 Notes

* The script automatically detects Public networks and temporarily switches them to Private to enable WinRM configuration.
  Disable this behavior with `-SkipNetworkFix` if you prefer manual control.
* In HTTPS mode:

  * A **self-signed certificate** is created if no valid certificate exists.
  * The certificate’s CN matches the host IP and computer name.
* For production use:

  * Replace the self-signed certificate with a CA-issued certificate.
  * Restrict `TrustedHosts` to specific trusted ranges.
  * Disable `AllowUnencrypted` for better security.

---

## 🧪 Troubleshooting

Use these PowerShell commands to verify or diagnose WinRM configuration:

### Check existing listeners

```powershell
winrm enumerate winrm/config/listener
```

### Test local WinRM connectivity

```powershell
Test-WsMan localhost
```

### Check WinRM firewall rules

```powershell
Get-NetFirewallRule | Where-Object DisplayName -like "*WinRM*"
```

### Restart WinRM service

```powershell
Restart-Service WinRM -Force
```

### Check authentication and encryption settings

```powershell
winrm get winrm/config/service
winrm get winrm/config/service/auth
```

If issues persist, rerun the script with `-Verbose` for detailed output:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Configure-WinRMForAnsible.ps1 -Verbose
```

---

## 🪄 Re-run Anytime

The script checks existing listeners, certificates, and firewall rules before applying changes.
It’s safe to re-run on multiple systems or during provisioning.

---

## 📄 License

MIT License — use, modify, and distribute freely.
