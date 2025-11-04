# WinUserSleuth — Username Enumerator & Validator

**WinUserSleuth** is a focused, professional guest-only SMB username enumeration and validation tool.
It enumerates candidate accounts using `impacket-lookupsid` and `netexec` (guest binding), filters noisy tokens, auto-detects the Kerberos domain, and validates candidates using `kerbrute`. The tool is optimized for accurate, compact results and supports parallel enumeration.

> ⚠️ **Legal / ethical reminder:** Only run this tool against systems you own or where you have **explicit written permission** to test. Unauthorized scanning or brute-forcing is illegal.

---

## Features

* Single-phase **Guest-only** enumeration (no anonymous phase).
* Parallel enumeration of `impacket-lookupsid` and `netexec` to reduce runtime.
* Heuristic filtering to remove noisy tokens (pipes, SIDs, group labels, machine accounts, etc.).
* Automatic domain detection for `kerbrute`.
* Validates candidate usernames via `kerbrute userenum -d <domain> --dc <target>`.
* Kerbrute runs silently by default; script parses and prints only confirmed usernames.
* Default confirmed-output file: `./user.txt` (override with `-o`).
* Minimal, professional console output.

---

## Requirements

* `bash` (POSIX shell)
* `impacket` (script `impacket-lookupsid` available)
* `netexec` (or equivalent providing `netexec smb ...`)
* `kerbrute` binary in `PATH`
* Standard GNU utilities: `grep`, `sed`, `awk`, `sort`, `tee`, `mktemp`

> Install examples (Kali/Debian-like):
>
> ```bash
> sudo apt update
> sudo apt install -y python3 python3-pip
> pip3 install impacket
> # Download kerbrute binary and place into /usr/local/bin or ~/bin, chmod +x
> ```

---

## Install / Quick setup

1. Save the script as `winusersleuth.sh` in your tools folder.
2. Make it executable:

   ```bash
   chmod +x winusersleuth.sh
   ```
3. Ensure `impacket-lookupsid`, `netexec`, and `kerbrute` are installed and in your `PATH`.

---

## Usage

```bash
./winusersleuth.sh -t <TARGET> [options]

# Examples
./winusersleuth.sh -t 10.201.44.39
./winusersleuth.sh -t dc.corp.local -o confirmed_users.txt
./winusersleuth.sh -t 10.201.44.39 --verbose
```

### Options

* `-t <TARGET>` — **(required)** Target IP or hostname.
* `-o <OUTFILE>` — Save confirmed usernames to `<OUTFILE>` (default: `./user.txt`).
* `--verbose` — Show debug info for pre/post steps (Kerbrute remains hidden by default).
* `-h` — Show help.

---

## Example output

```
🔍 WinUserSleuth v2.x — Guest-only SMB Enumerator + Kerbrute Validator

[*] Target: 10.201.44.39
[*] Confirmed output file: ./user.txt

[+] Enumerating via impacket-lookupsid and netexec (guest)...
[*] Candidate usernames for Kerbrute: 17
[*] Detected domain for Kerbrute: LAB-ENTERPRISE

[+] Running Kerbrute (hidden)...

✅ Kerbrute confirmed usernames:
atlbitbucket
banana
bitbucket
Cake
contractor-temp
joiner
korone
nik
replication
spooks
varg

→ Total confirmed users: 11
→ Saved to: ./user.txt

[+] Scan finished.
```

---

## Output files

* `./user.txt` (default) — confirmed usernames, one per line.
* Temporary raw files are created in `/tmp` during execution and removed afterward.

---

## License & Use

This tool is intended for authorized security testing and research only. Do not use it for unauthorized scanning or brute forcing

---
