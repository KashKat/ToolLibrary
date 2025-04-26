# MSSQL-LinkedServerTool

Reference https://github.com/hackinaggie/OSEP-Tools-v2/tree/main/Active_Directory/sql

Note - This VS Project Solution is just a refactoring of the original OSEP-Tools-v2 sql.exe tool which is used for exploitation of MSSQL instances.  
It was done to better understand the program and found creating helpers made it easier. 


Features include:
- Enumeration of MSSQL instances (calls setspn).
- Enumeration of linked SQL servers, users, users that can be impersonated, user context.
- Execute arbitrary SQL commands
- Enable XP_cmdshell or OLE objects on the current or a linked server
- Force authentication of SQL server to an SMB share for use with ntlmrelayx
- Execute XP_cmdshell or OLE object commands on the current or a linked server

These features are all functional over bidirectional links.
`Installutil` bypass is baked in so this tool can be run on a machine with Application whitelisting in place. Note that when running `sql.exe` with `installutil`, all switches must be passed BEFORE you specify `sql.exe`.

### Details
Below is the help message explaining the available flags.
```
MSSQL Linked Server Tool

Compatible with InstallUtil AppLocker bypass; Use /s=SQL05 syntax instead of /s:SQL05 with InstallUtil.

Modes:
 /q - Query  Query a domain for MSSQL SPN's
 /e - Enumerate   Find Linked MSSQL instances and enumerate permissions
 /c - Command Execute sql queries on the logged in server
 /f - Enable  Enable features like XP_cmdshell and OLE objects on a Linked server
 /x - Command Execute commands via XP_cmdshell on a linked server
 /o - Command Execute commands via OLE object on a linked server
 /h - Force SQL server to authenticate to an SMB share in order to capture hash for use with ntlmrelayx

Options:
 /l: Login (username) to authenticate with (default: Windows credentials)
 /p: Password to authenticate with
 /d: Database to connect to (default: Master)
 /s: Server to connect to (default: Localhost)
 /i: User to impersonate. Enter "dbo" to try and auth as dbo in the msdb database.
 /t: Tunnel through a Linked MSSQL server in order to complete tasks on one of its Linked servers.
```