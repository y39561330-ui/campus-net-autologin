' RunHidden.vbs -- launch Connect-CampusNet.ps1 completely hidden (no console window flash).
' Used by the scheduled task and the startup shortcut.
'
' Usage:  wscript.exe //B //Nologo RunHidden.vbs [extra arguments for Connect-CampusNet.ps1]
'
' Why: powershell.exe -WindowStyle Hidden still creates a console window for a split second
'      before hiding it. WScript.Shell.Run with window style 0 never creates one.

Option Explicit

Dim fso, sh, baseDir, scriptPath, cmd, i

Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")

baseDir    = fso.GetParentFolderName(WScript.ScriptFullName)
scriptPath = baseDir & "\Connect-CampusNet.ps1"

cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & scriptPath & """"

For i = 0 To WScript.Arguments.Count - 1
    cmd = cmd & " " & WScript.Arguments(i)
Next

' 0 = hidden window, False = do not wait for it to finish
sh.Run cmd, 0, False
