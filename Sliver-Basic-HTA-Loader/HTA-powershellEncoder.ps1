# Read the contents of the PowerShell script as text
$scriptContent = Get-Content -Path ".\sliver.xml" -Raw

# Convert the string to bytes (UTF8 encoding)
$bytes = [System.Text.Encoding]::UTF8.GetBytes($scriptContent)

# Encode the byte array as Base64
$base64 = [Convert]::ToBase64String($bytes)

# Write the Base64 string to a text file
Set-Content -Path ".\encoded.txt" -Value $base64