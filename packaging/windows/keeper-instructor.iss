#ifndef PackageRoot
  #error PackageRoot must identify the built keeper-desktop directory
#endif
#ifndef OutputDir
  #error OutputDir must identify the installer output directory
#endif
#ifndef SetupIcon
  #error SetupIcon must identify the Keeper icon
#endif
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{9D3D12B0-3384-4C47-86E3-E8B8941B7BB0}
AppName=Keeper
AppVersion={#AppVersion}
AppPublisher=Keeper Project
AppPublisherURL=https://github.com/Cos229-239/2608_Team04
DefaultDirName={localappdata}\Programs\Keeper
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=Keeper-{#AppVersion}-Instructor-Setup-Unsigned
SetupIconFile={#SetupIcon}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
Uninstallable=no
CreateAppDir=no
UsePreviousAppDir=no
VersionInfoVersion={#AppVersion}
VersionInfoProductName=Keeper Instructor Inspection Setup
VersionInfoDescription=Installs the local Keeper desktop inspection build

[Files]
Source: "{#PackageRoot}\*"; DestDir: "{tmp}\KeeperPayload"; Flags: recursesubdirs createallsubdirs deleteafterinstall ignoreversion

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{tmp}\KeeperPayload\install-keeper-desktop.ps1"""; WorkingDir: "{tmp}\KeeperPayload"; StatusMsg: "Verifying and installing Keeper..."; Flags: waituntilterminated

[Code]
procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel1.Caption := 'Install Keeper for instructor inspection';
  WizardForm.WelcomeLabel2.Caption :=
    'This setup installs the local Keeper desktop application for the current Windows user.' + #13#10 + #13#10 +
    'The package is an unsigned classroom inspection build. Windows may display a publisher warning.';
end;
