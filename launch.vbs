Set WshShell = CreateObject("WScript.Shell")
WshShell.CurrentDirectory = "C:\Users\delln\OneDrive\Desktop\projects\network vulnerability scanner"
WshShell.Run Chr(34) & "C:\Users\delln\OneDrive\Desktop\projects\network vulnerability scanner\run_service.bat" & Chr(34), 1, False
