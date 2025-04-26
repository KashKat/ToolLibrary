# Macro Shellcode Runners
Most of the the tools are from hackinaggie's OSEP-Tools-v2 and customized in some ways to work with Sliver C2

## vbaWordPsCradle.vbs



## vbMacroObfuscate.ps1
Powershell script to generate Caesar Cipher code for vbaWordPsCradle.vbs. Make sure offsets match for encrypt/decrypt. First output is download cradle, last is app name for app name check before running.

Modify the respective inputs such as line 1 for powershell code runner, line 68 to match the exact file name of .docm containing macro for heuristics bypass attempt. 


### References
https://github.com/hackinaggie/OSEP-Tools-v2/tree/main/Macros