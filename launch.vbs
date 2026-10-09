Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "D:\PROJECTS\network vulnerability scanner"
WshShell.Run Chr(34) & "D:\PROJECTS\network vulnerability scanner\run_service.bat" & Chr(34), 1, False
