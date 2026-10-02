# webdav-check

A full-spectrum NTLM coercion and relay viability scanner that goes beyond SMB-only tools like NetExec. It detects WebDAV coercion opportunities on hosts **with or without SMB**, which is the key to finding HTTP-based coerced authentication paths where MIC is not enforced, making LDAP and LDAPS relay possible.

## Why This Exists

Tools like NetExec (`nxc smb`) only discover hosts over SMB (port 445). If a host has SMB closed, it won't show up at all, even if it's fully vulnerable to coercion via RPC and could send WebDAV-based authentication over HTTP. This scanner fills that gap by probing every viable coercion and relay path independently.

## What It Checks

**Phase 1 - Port Discovery:** Scans 14 common ports (HTTP, HTTPS, RPC, SMB, LDAP, LDAPS, Kerberos, WinRM, and others) to map the attack surface.

**Phase 2 - WebDAV Detection (no SMB needed):** Sends HTTP OPTIONS and PROPFIND requests to detect WebDAV support purely over HTTP. Also checks for NTLM challenges on HTTP, HTTPS, and WinRM ports. This is the primary check that SMB-only tools miss entirely.

**Phase 3 - RPC Coercion Viability:** Probes the RPC Endpoint Mapper (port 135) to confirm MS-EFSR (PetitPotam), MS-RPRN (PrinterBug), and MS-DFSNM coercion paths are reachable.

**Phase 4 - SMB WebClient Service Query:** When SMB is available and credentials are provided, queries the WebClient service state via SVCCTL. This is a bonus check on top of the HTTP-based detection.

**Phase 5 - LDAP Relay Target Assessment:** Tests LDAP signing and LDAPS channel binding enforcement to determine if relay to LDAP or LDAPS is viable.

**Phase 6 - Verdict:** Combines all findings and flags full attack chains. The critical finding is WebDAV coercion (no MIC) combined with LDAP signing or channel binding not required, which gives a complete coercion-to-relay path.

## Requirements

Python 3.7 or later. No dependencies are required for the core HTTP and RPC checks. Optional packages enable deeper checks:

```
pip install impacket ldap3
```

`impacket` enables authenticated WebClient service queries over SMB. `ldap3` enables LDAP signing and channel binding checks. The scanner runs without either and reports which checks were skipped.

## Usage

### Basic scan of a single host

```bash
python3 webdav-check.py -t 10.0.0.11 -l 10.200.0.15
```

### Scan a subnet with credentials

```bash
python3 webdav-check.py -t 10.0.0.0/24 -l 10.200.0.15 -u russ -p 'P@ssword123' -d corp.com
```

### Scan specific hosts (comma-separated)

```bash
python3 webdav-check.py -t 10.0.0.11,10.0.0.19,10.0.0.60 -l 10.200.0.15 -u russ -p 'P@ssword123' -d corp.com
```

### Scan from a target file

```bash
python3 webdav-check.py -t targets.txt -l 10.200.0.15 -u russ -p 'P@ssword123' -d corp.com
```

Where `targets.txt` contains one IP, hostname, or CIDR per line:

```
10.0.0.11
10.0.0.19
10.0.0.60
172.16.5.0/24
```

### Windows (PowerShell)

```powershell
py -3.11 webdav-check.py -t 10.0.0.0/24 -l 10.200.0.15 -u russ -p "P@ssword123" -d corp.com
```

### Adjust timeout for slow networks

```bash
python3 webdav-check.py -t 10.0.0.0/24 -l 10.200.0.15 --timeout 5
```

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-t`, `--targets` | Yes | IP address, CIDR subnet, comma-separated list, or path to a file with one target per line |
| `-l`, `--listener` | Yes | Your listener IP where coerced authentication callbacks would be sent |
| `-u`, `--username` | No | Domain username for authenticated checks (SMB service query, LDAP signing) |
| `-p`, `--password` | No | Password for the domain account |
| `-d`, `--domain` | No | Domain name (defaults to `.`) |
| `--timeout` | No | Connection timeout in seconds (defaults to 3) |

## Understanding the Output

The scanner uses color-coded tags for every step so you can see exactly where each check succeeded or failed:

- **[PASS]** (green) - Check passed, the control is in place (good for the defender, bad for the attacker)
- **[FAIL]** (gray) - Check could not run (port closed, connection failed, missing dependency)
- **[WARN]** (yellow) - Something worth investigating (service stopped but startable, Negotiate offered)
- **[CRIT]** (red) - Exploitable finding (WebDAV active, NTLM over HTTP, LDAP signing not required)
- **[INFO]** (cyan) - Informational context
- **[STEP]** (white) - Shows which check is running right now

A **CRITICAL** chain in the final verdict means both sides of the attack are confirmed: the target can be coerced into sending HTTP-based NTLM authentication (which carries no MIC), and a relay target accepts that authentication without enforcing signing or channel binding.

## How WebDAV Coercion Differs from SMB Coercion

When a host is coerced via PetitPotam or PrinterBug, it normally authenticates back to the attacker over SMB (port 445). That SMB-based NTLM authentication includes a MIC (Message Integrity Code), which prevents relaying it to LDAP or LDAPS.

WebDAV coercion changes the callback protocol from SMB to HTTP. When the coerced host has the WebClient service running, it follows UNC paths over HTTP instead of SMB. HTTP-based NTLM authentication does not include MIC enforcement, which means the captured authentication can be relayed to LDAP or LDAPS. This is the most reliable path to coercion-based domain compromise in modern environments.

## Disclaimer

This tool is intended for authorized penetration testing and security assessments only. Always obtain written authorization before testing. The authors are not responsible for misuse.
