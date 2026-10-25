' 1-Click Silent Desktop Launcher for PacketSentinel
' Launches the native desktop GUI directly without leaving a terminal window open.
Set FSO = CreateObject("Scripting.FileSystemObject")
Set WshShell = CreateObject("WScript.Shell")
strCurrentDir = FSO.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = strCurrentDir
WshShell.Run "cmd /c run.bat --ui", 0, False
