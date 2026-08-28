#ifndef PayloadRoot
  #error PayloadRoot must identify the full-machine payload
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
#ifndef OutputSuffix
  #define OutputSuffix "-Unsigned"
#endif

[Setup]
AppId={{5E814A4A-14C6-4F80-9B6B-A2F6E43E8B66}
AppName=Keeper Full Machine
AppVersion={#AppVersion}
AppPublisher=Keeper Project
DefaultDirName={autopf}\Keeper
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=Keeper-{#AppVersion}-Full-Machine-Setup{#OutputSuffix}
SetupIconFile={#SetupIcon}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
Uninstallable=no
CreateAppDir=no
UsePreviousAppDir=no
VersionInfoVersion={#AppVersion}
VersionInfoProductName=Keeper Full Machine Setup
VersionInfoDescription=Installs KeeperAuthority, Provider Host, enrollment, and Keeper Desktop

[Files]
Source: "{#PayloadRoot}\*"; DestDir: "{tmp}\KeeperMachinePayload"; Flags: recursesubdirs createallsubdirs deleteafterinstall ignoreversion

[Run]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{tmp}\KeeperMachinePayload\install-machine-authority.ps1"" -PayloadRoot ""{tmp}\KeeperMachinePayload"""; WorkingDir: "{tmp}\KeeperMachinePayload"; StatusMsg: "Installing and verifying KeeperAuthority..."; Flags: waituntilterminated
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{tmp}\KeeperMachinePayload\install-user-components.ps1"" -PayloadRoot ""{tmp}\KeeperMachinePayload"""; WorkingDir: "{tmp}\KeeperMachinePayload"; StatusMsg: "Installing Provider Host and Keeper Desktop..."; Flags: waituntilterminated runasoriginaluser

[Code]
procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel1.Caption := 'Install Keeper on this Windows computer';
  WizardForm.WelcomeLabel2.Caption :=
    'Setup installs the protected KeeperAuthority service for the machine, then installs and enrolls the Provider Host and Keeper Desktop for your Windows account.' + #13#10 + #13#10 +
    'Founder confirmation is required during enrollment. Setup never copies provider credentials.';
end;
