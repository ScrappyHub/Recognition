; Inno Setup script for a single Setup.exe installer.
; Requires Inno Setup (https://jrsoftware.org/isdl.php) to COMPILE:
;     "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer\recognition.iss
; Produces installer\Recognition-Setup.exe (a downloadable, double-clickable installer).
;
; Prerequisite: run scripts\RUN_PACKAGE_DIST_V1.ps1 first so dist\recognition\ exists.

[Setup]
AppId={{A9E2F3C1-0B7A-4D6E-9C21-7E4B1F0A55A9}
AppName=Recognition
AppVersion=1.0.0
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

[Run]
Filename: "{app}\browser\RecognitionBrowser.exe"; Description: "Launch Recognition now"; Flags: nowait postinstall skipifsilent
