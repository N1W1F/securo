Set shell = CreateObject("WScript.Shell")
shell.CurrentDirectory = "C:\Users\PC\Documents\threat-intel-agent\app"
shell.Run """C:\Users\PC\AppData\Local\Programs\Python\Python312\pythonw.exe"" desktop_app.py", 1, False
