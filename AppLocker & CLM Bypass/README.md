# AppLocker
AppLocker is a windows feature designed to control which users can run what programs. Uses rules for executables with a Publisher signature; allow anything signed by Microsoft - File Path, File Hash or by User or Security Group Scope assignment. 

AppLocker covers the following filetypes:
Executables - .exe, .dll
Installers - .msi, msp
Scripts - .bat, .cmd, .vbs, .js, .ps1

** Not to be confused by Constrained Language Mode (CLM) which restricts PowerShell usage to a safe subset, often restricting scripts and prevent abuse. ** 

