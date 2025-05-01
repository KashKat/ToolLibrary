# MSBuild

## Overview

Microsoft Build Engine `msbuild.exe` is used to compile and build applications from XML-Based project files in the form of `.csproj`, and `.vbproj`.&#x20;

{% hint style="info" %}
In most scenarios, the payload will be .xml but can be renamed to .csproj to ensure exeuction.&#x20;
{% endhint %}

```bash
# utility location (32-bit)
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
# utility location (64 bit)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe
```

The proess of code execution is within the inline tasks of the xml file. This allows one to insert .NET Assembly (.cs) code into the xml payload and execute with msbuild.exe and reference the csproj file.&#x20;

```
# Execution example
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe runner.xml
```

***

## XML Template

The default template.xml file can be replaced with most .cs code projects that are used for code execution, including amsi bypasses, shellcode runners, etc.

By Default, the template contains a basic shellcode runner with an xor'd staged payload

### References

MSBuild XML: ToolLibrary/AppLocker-CLM/MSBuild/template.xml

***

## Process Hollowing

### References

MSBuild XML: ToolLibrary/AppLocker-CLM/MSBuild/pshollow.xml\
Original Payload: ToolLibrary/ProcessHollowing/pshollow.cs\
XOR Encoder: ToolLibrary/XOR-Encoder/xorencoder.cs

### Steps

1. Generate msfvenom payload
2. Compile xorendcoder.cs project to encode msfvenom payload
3. Add XOR'd payload to pshollow.xml

***

## Sliver Payload

### References

MSBuild XML: ToolLibrary/AppLocker-CLM/MSBuild/Sliver.xml
