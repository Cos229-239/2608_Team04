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
SetupLogging=yes
VersionInfoVersion={#AppVersion}
VersionInfoProductName=Keeper Full Machine Setup
VersionInfoDescription=Installs KeeperAuthority, Provider Host, enrollment, and Keeper Desktop

[Files]
Source: "{#PayloadRoot}\*"; DestDir: "{tmp}\KeeperMachinePayload"; Flags: recursesubdirs createallsubdirs dontcopy noencryption

[Code]
var
  ComponentsAttempted: Boolean;
  ComponentError: String;

function RunComponent(ScriptName: String; OriginalUser: Boolean): String;
var
  Started: Boolean;
  ResultCode: Integer;
  ProgramPath, Parameters, Payload: String;
begin
  Payload := ExpandConstant('{tmp}\KeeperMachinePayload');
  ProgramPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters := '-NoProfile -ExecutionPolicy Bypass -File "' + Payload + '\' + ScriptName + '" -PayloadRoot "' + Payload + '"';
  Log('Starting Keeper component: ' + ScriptName);
  if OriginalUser then
    Started := ExecAsOriginalUser(ProgramPath, Parameters, Payload, SW_HIDE, ewWaitUntilTerminated, ResultCode)
  else
    Started := Exec(ProgramPath, Parameters, Payload, SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Result := '';
  if (not Started) or (ResultCode <> 0) then
    Result := ScriptName + ' failed (code ' + IntToStr(ResultCode) + '). Keeper setup is incomplete. ' +
      'See the Keeper-machine-*.log files in your Windows temp folder and the Setup log. ' +
      'Existing data has not been reset. Close setup before trying again.';
  Log('Keeper component result: ' + ScriptName + '; code=' + IntToStr(ResultCode));
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  { A nonempty result stops at Preparing to Install with a failure exit code.
    Unlike [Run], child failures cannot reach the successful completion page.
    Cache the result so the wizard cannot silently repeat a failed phase. }
  if not ComponentsAttempted then begin
    ComponentsAttempted := True;
    ComponentError := 'Keeper setup did not complete.';
    try
      WizardForm.PreparingLabel.Caption := 'Extracting and verifying Keeper components. This may take a few minutes...';
      ExtractTemporaryFiles('{tmp}\KeeperMachinePayload\*');
      WizardForm.PreparingLabel.Caption := 'Installing and verifying KeeperAuthority...';
      ComponentError := RunComponent('install-machine-authority.ps1', False);
      if ComponentError = '' then begin
        WizardForm.PreparingLabel.Caption := 'Verifying Provider Host, enrollment, and Keeper Desktop...';
        ComponentError := RunComponent('install-user-components.ps1', True);
      end;
    except
      ComponentError := 'Keeper setup stopped: ' + GetExceptionMessage;
      Log(ComponentError);
    end;
  end;
  Result := ComponentError;
end;

procedure InitializeWizard;
begin
  WizardForm.WelcomeLabel1.Caption := 'Install Keeper on this Windows computer';
  WizardForm.WelcomeLabel2.Caption :=
    'Setup installs KeeperAuthority, Provider Host, and Keeper Desktop. On an existing setup, verified compatible services and enrollment are retained while the desktop is repaired or upgraded.' + #13#10 + #13#10 +
    'Founder confirmation is required during enrollment. Setup never copies provider credentials.';
end;
