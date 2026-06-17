# pypi-postscan-hardening
Incident Response and post-compromise hardening toolkit for Linux systems following suspected PyPI supply chain attacks. Includes false-positive verification, systemd auditing, pip hardening, C2 blocking, and package integrity validation.

# PyPI IR Hardening

Incident Response and post-compromise hardening toolkit for Linux systems following suspected PyPI supply chain attacks.

The script performs:

* False positive verification of suspicious services
* Debug shell detection and remediation
* Python process investigation
* Known C2 domain blocking
* pip hardening
* Package blacklist enforcement
* Virtual environment integrity validation
* Detection rule tuning recommendations

---

## Features

### Incident Response

* Verify suspicious systemd services
* Audit Ubuntu services falsely flagged as malicious
* Inspect suspicious Python processes
* Verify executable locations and ownership

### System Hardening

* Disable and mask `debug-shell.service`
* Block known C2 domains in `/etc/hosts`
* Enforce official PyPI repositories
* Remove unsafe package mirrors
* Configure secure pip defaults

### Supply Chain Protection

Blocks installation of known malicious package versions:

```text
lightning!=2.6.2,!=2.6.3

pytorch-lightning!=2.6.2,!=2.6.3

durabletask!=1.4.1,!=1.4.2,!=1.4.3
```

Implemented through:

```text
/etc/pip-security-constraints.txt
```

---

## What The Script Checks

### 1. False Positive Verification

Verifies that Ubuntu services such as:

* ua-reboot-cmds.service
* esm-cache.service
* ubuntu-advantage.service
* ua-timer.service
* apt-news.service

are legitimate and owned by root.

---

### 2. Debug Shell Detection

Checks:

```bash
debug-shell.service
```

If enabled:

* Stops the service
* Disables it
* Masks it permanently

to prevent unauthenticated root access on tty9.

---

### 3. Python Process Investigation

Inspects:

```bash
/proc/<pid>
```

Collects:

* Executable path
* Command line
* Working directory
* Running user

Warns if Python executes from:

```text
/tmp
/var/tmp
/dev/shm
```

which are common malware execution paths.

---

### 4. C2 Domain Blocking

Automatically adds:

```text
0.0.0.0 ddjidd564.github.io
```

to:

```text
/etc/hosts
```

---

### 5. pip Hardening

Creates:

```text
/etc/pip.conf
```

with:

```ini
index-url = https://pypi.org/simple/
no-user-site = true
```

and removes unsafe mirrors.

---

## Installation

Clone:

```bash
git clone https://github.com/YOUR_USERNAME/pypi-ir-hardening.git

cd pypi-ir-hardening
```

Make executable:

```bash
chmod +x pypi_harden.sh
```

Run:

```bash
sudo ./pypi_harden.sh
```

---

## Example Output

```text
[DONE] debug-shell.service disabled and masked

[DONE] Created /etc/pip.conf

[DONE] C2 domain blocked

Machine status:
NOT compromised by PyPI supply chain attacks
```

---

## Tested On

* Ubuntu 24.04 LTS
* Python 3.12
* systemd 255+
* pip 24+

---

## Security Notes

This tool is intended for:

* Incident Response
* Post-compromise validation
* PyPI supply chain investigations
* Linux security hardening

It is not a malware removal framework and should be used together with:

* EDR
* SIEM
* IOC scanning
* Threat hunting workflows

---

## License

MIT License

---

## GitHub Topics

```text
incident-response
linux-security
pypi
supply-chain-security
cybersecurity
threat-hunting
blue-team
pip
systemd
hardening
malware-analysis
soc
```
