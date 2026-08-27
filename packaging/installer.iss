#define MyAppName "Arenyxa"
#define MyAppVersion "8.1"
#define MyAppPublisher "Arenyxa Contributors"
#define MyAppExeName "Arenyxa.exe"
#define ProjectRoot ".."

[Setup]

AppId={{62ED5A19-19D3-402F-8819-D06C9D4A768B}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\Arenyxa
DefaultGroupName=Arenyxa
AllowNoIcons=yes
LicenseFile={#ProjectRoot}\LICENSE
OutputDir={#ProjectRoot}\dist\installer
OutputBaseFilename=Arenyxa_V8.1_Setup_x64
SetupIconFile={#ProjectRoot}\src\arenyxa\resources\icons\arenyxa.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
ChangesAssociations=yes

[Languages]
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加快捷方式："; Flags: unchecked
Name: "windowsservice"; Description: "安装 Arenyxa Windows Service（管理员模式）"; GroupDescription: "企业运行时："; Flags: unchecked; Check: IsAdminInstallMode

[Files]
Source: "{#ProjectRoot}\dist\Arenyxa\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\Arenyxa"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Arenyxa"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Registry]

Root: HKA; Subkey: "Software\Classes\.arenyxa"; ValueType: string; ValueName: ""; ValueData: "Arenyxa.Project"; Flags: uninsdeletevalue
Root: HKA; Subkey: "Software\Classes\Arenyxa.Project"; ValueType: string; ValueName: ""; ValueData: "Arenyxa Project"; Flags: uninsdeletekey
Root: HKA; Subkey: "Software\Classes\Arenyxa.Project\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#MyAppExeName},0"
Root: HKA; Subkey: "Software\Classes\Arenyxa.Project\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[InstallDelete]

Type: files; Name: "{autodesktop}\Arenyxa.lnk"
Type: files; Name: "{group}\Arenyxa.lnk"

[Run]
Filename: "{app}\ArenyxaService.exe"; Parameters: "--install --data-dir ""{commonappdata}\Arenyxa\Runtime"""; Description: "安装 Arenyxa Windows Service"; Flags: runhidden waituntilterminated; Tasks: windowsservice; Check: IsAdminInstallMode
Filename: "{app}\{#MyAppExeName}"; Description: "启动 Arenyxa"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{app}\ArenyxaService.exe"; Parameters: "--remove"; Flags: runhidden waituntilterminated skipifdoesntexist; RunOnceId: "ArenyxaServiceRemove"

[Code]
// Arenyxa-only installer: no legacy executable deletion is performed.
