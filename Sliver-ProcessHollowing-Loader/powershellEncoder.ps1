# Read raw bytes from the file
$bytes = Get-Content -Path ".\bin\x64\Release\SliverLoader.dll" -Encoding Byte

# Convert the byte array to Base64
$base64 = [Convert]::ToBase64String($bytes)

# Write the Base64 string to a text file
Set-Content -Path ".\SliverLoader_Base64.txt" -Value $base64