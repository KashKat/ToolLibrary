# GoHttpServer

A lightweight HTTP/HTTPS file server written in Go, designed for red teaming and penetration testing use cases which was inspired by @beauknowstech GUP https://github.com/beauknowstech/gup. 
This version supports:

- Configurable HTTP or HTTPS serving
- Directory listing and file serving
- Optional redirect rules based on URL path prefixes
- Logging of query parameters like `username` or `is64ps` (for payload staging context)
- JSON-based configuration for ease of reuse
- Works with bitsadmin which fails when using python3 -m http.server (sort of a pain)

---

## Features

The need for these features comes from working in various lab environments and Offsec OSEP challenges where I would replicate compiled binaries from source tools folder into a specific challenge folder, or replication of the same sliver shell code runners into a lab specific folder, which then organized things with replicated tested payloads, working payloads, sliver shellcode runner directory, etc, causing disorganization. 

I found myself constantly changing directories and serving `python3 -m http.server 80` on the fly, or having to re-compile a Portable Executable (PE) after an IP change or slight modification to a file name, or simply testing out a payload in some random directory. Instead of re-compiling, or generating new msfvenom stagers, I figured redirects were easier to configure where http://<kaliIP>/runner.ps1 would always point to the same sliver shellcode runner, or http://<kaliIP>/t/ will redirect to the same Tools folder and maintain my organizational folder structures. 

This would require running GoHttpServer from parent directory and organize labs, Tools, Sliver and Labs within sub-folders from where you run GoHttpServer. 

Feature List: 
- Serve files or entire directories from a specified base directory. 
- Redirect URL prefixes to different local folders.
- Choose between HTTP or HTTPS (self-signed certs supported).
- Supports `config.json` for reusable configuration without command-line arguments.
- Logs basic GET requests and Optional relevant URL query parameters. 

---

## Usage 

Basic Usage
```bash
# compile
go build -o GoHttpServer GoHttpServer.go

# Run with config: 
./GoHttpServer -config config.json

# Run without compiling
go run GoHttpServer.go -config config.json

# Run with arguments instead of -config
go run GoHttpServer.go \
  -port 443 \
  -use_https=true \
  -cert_file=server.crt \
  -key_file=server.key \
  -base_dir=./Challenge01 \
  -redirect="/runner.ps1=./Sliver/runner.ps1" \
  -redirect="/t/=./Challenge01/payloads"
```

HTTPS requires a valid cert.pem and key.pem file, can generate self-signed pair with: 
```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

Accepts user defined parameters in GET request from source, works well with @beauknowstech shellcode runner that provides parameter values returned from runner.ps1 in context of victim host. 
Example output of request to http://10.10.10.1/runner.ps1 with an active redirect of runner.ps1 > ./payloads/runner.ps1 in config.json
``` bash
[+] GET /payloads/runner.ps1 from 192.168.1.25
[i] Param 'username': alice
[i] Param 'is64ps': true
```

## Example `config.json`

```json
{
  "port": 80,
  "use_https": false,
  "cert_file": "./sliver/sslCerts/server.crt",
  "key_file": "./sliver/sslCerts/server.key",
  "base_dir": "./Challenge05",
  "redirects": {
    "/runner.ps1": "./sliver/runner.ps1",
    "/p/": "./Challenge05/payloads",
    "/t/": "./tools"
  }
}
```

## Example folder directory
```
/PEN300
├── GoHttpServer.go
├── config.json
├── Challenge01/
│   ├── payloads/
│   │   ├── payload1.bin
│   │   └── payload2.sh
│   └── runner.ps1
├── Sliver/
│   └── runner.ps1
├── Exercise01/
│   └── payloads/
└── Tools/
    └── Ligolo-NG/
    └── PrintSpooler/
```

## Argument List
```
|Flag |	Description |
| --- | --- |
| -port |	Port number to run the server on (e.g. 8080) |
| -use_https |	true or false to enable/disable HTTPS |
| -cert_file |	Path to TLS certificate (used if HTTPS is on) |
| -key_file |	Path to TLS private key (used if HTTPS is on) |
| -base_dir |	Root directory to serve when accessing / |
```
-redirect	Redirect mapping from URI to filesystem path
