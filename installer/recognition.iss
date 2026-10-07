; Inno Setup script for a single Setup.exe installer.
; Requires Inno Setup (https://jrsoftware.org/isdl.php) to COMPILE:
;     "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\recognition.iss
; Produces installer\Recognition-Setup.exe (a downloadable, double-clickable installer).
;
; Prerequisite: run scripts\RUN_PACKAGE_DIST_V1.ps1 first so dist\recognition\ exists.

[Setup]
AppId={{A9E2F3C1-0B7A-4D6E-9C21-7E4B1F0A55A9}
AppName=Recognition
AppVersion=1.3.2
AppPublisher=ScrappyHub
DefaultDirName={localappdata}\Recognition
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=.
OutputBaseFilename=Recognition-Setup
SetupIconFile=..\browser\recognition.ico
UninstallDisplayIcon={app}\browser\RecognitionBrowser.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Files]
Source: "..\dist\recognition\*"; DestDir: "{app}"; Excludes: "runtime\*,packets\*,payload\*,dist\*"; Flags: recursesubdirs createallsubdirs ignoreversion

[Icons]
Name: "{autoprograms}\Recognition"; Filename: "{app}\browser\RecognitionBrowser.exe"; WorkingDir: "{app}\browser"
Name: "{autodesktop}\Recognition";  Filename: "{app}\browser\RecognitionBrowser.exe"; WorkingDir: "{app}\browser"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

; Lets Windows list Recognition under Settings > Default apps. It does not make Recognition the default: the person chooses that.
[Registry]
Root: HKCU; Subkey: "Software\Classes\RecognitionURL"; ValueType: string; ValueData: "Recognition URL"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\RecognitionURL"; ValueType: string; ValueName: "URL Protocol"; ValueData: ""
Root: HKCU; Subkey: "Software\Classes\RecognitionURL\DefaultIcon"; ValueType: string; ValueData: "{app}\browser\RecognitionBrowser.exe,0"
Root: HKCU; Subkey: "Software\Classes\RecognitionURL\shell\open\command"; ValueType: string; ValueData: """{app}\browser\RecognitionBrowser.exe"" ""%1"""
Root: HKCU; Subkey: "Software\Classes\RecognitionHTML"; ValueType: string; ValueData: "Recognition HTML Document"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Classes\RecognitionHTML\DefaultIcon"; ValueType: string; ValueData: "{app}\browser\RecognitionBrowser.exe,0"
Root: HKCU; Subkey: "Software\Classes\RecognitionHTML\shell\open\command"; ValueType: string; ValueData: """{app}\browser\RecognitionBrowser.exe"" ""%1"""
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition"; ValueType: string; ValueData: "Recognition"; Flags: uninsdeletekey
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition\DefaultIcon"; ValueType: string; ValueData: "{app}\browser\RecognitionBrowser.exe,0"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition\shell\open\command"; ValueType: string; ValueData: """{app}\browser\RecognitionBrowser.exe"""
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition\Capabilities"; ValueType: string; ValueName: "ApplicationName"; ValueData: "Recognition"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition\Capabilities"; ValueType: string; ValueName: "ApplicationDescription"; ValueData: "Governed, private browser"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition\Capabilities"; ValueType: string; ValueName: "ApplicationIcon"; ValueData: "{app}\browser\RecognitionBrowser.exe,0"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition\Capabilities\URLAssociations"; ValueType: string; ValueName: "http"; ValueData: "RecognitionURL"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition\Capabilities\URLAssociations"; ValueType: string; ValueName: "https"; ValueData: "RecognitionURL"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition\Capabilities\FileAssociations"; ValueType: string; ValueName: ".htm"; ValueData: "RecognitionHTML"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition\Capabilities\FileAssociations"; ValueType: string; ValueName: ".html"; ValueData: "RecognitionHTML"
Root: HKCU; Subkey: "Software\Clients\StartMenuInternet\Recognition\Capabilities\FileAssociations"; ValueType: string; ValueName: ".xhtml"; ValueData: "RecognitionHTML"
Root: HKCU; Subkey: "Software\RegisteredApplications"; ValueType: string; ValueName: "Recognition"; ValueData: "Software\Clients\StartMenuInternet\Recognition\Capabilities"; Flags: uninsdeletevalue

[Run]
Filename: "{app}\browser\RecognitionBrowser.exe"; Description: "Launch Recognition now"; Flags: nowait postinstall skipifsilent
