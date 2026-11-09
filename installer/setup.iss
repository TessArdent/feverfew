; Builds dist\setup.exe. Run build.ps1 instead of calling this directly.

#ifndef AppVersion
  #define AppVersion "1.1.0"
#endif

[Setup]
AppId={{7C6E2B1A-4F7D-4B59-9A3E-2D5C8E1F6A40}
AppName=Feverfew
AppVersion={#AppVersion}
AppVerName=Feverfew {#AppVersion}
AppPublisher=TessArdent
AppPublisherURL=https://github.com/TessArdent/feverfew
DefaultDirName={autopf}\Feverfew
DisableProgramGroupPage=yes
DisableDirPage=yes
; Installs for the current user, so setup needs no admin prompt. The app asks when it scans.
PrivilegesRequired=lowest
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=setup
SetupIconFile=..\assets\feverfew.ico
UninstallDisplayIcon={app}\Feverfew.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"

[Files]
Source: "..\src\Feverfew\bin\Release\net48\Feverfew.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Feverfew"; Filename: "{app}\Feverfew.exe"
Name: "{autodesktop}\Feverfew"; Filename: "{app}\Feverfew.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Feverfew.exe"; Description: "Open Feverfew now"; Flags: nowait postinstall skipifsilent

[Code]
function InitializeSetup(): Boolean;
begin
  Result := IsDotNetInstalled(net48, 0);
  if not Result then
    SuppressibleMsgBox('Feverfew needs .NET Framework 4.8. Install it from Microsoft, then run this setup again.', mbCriticalError, MB_OK, IDOK);
end;
