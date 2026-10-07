#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif

[Setup]
AppId={{4C6A6E5D-6E9E-4C2A-8B9B-0A6A5F5C7D2E}
AppName=pf
AppVersion={#MyAppVersion}
AppPublisher=provablyfine
AppPublisherURL=https://docs.provablyfine.net
; Installs for the current user by default, in %LOCALAPPDATA%\Programs\pf, and
; needs no elevation. The user can choose "all users" in the installer, or pass
; /ALLUSERS, to install in Program Files. A host needs that: sshd only runs a
; command that only administrators can change. The OpenSSH Authentication
; Agent service (if disabled) is a separate, one-time, admin-required step the
; user is told about, not something this installer attempts itself.
; pf.exe is a 64-bit program. Without these lines, {autopf} is Program Files (x86).
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
DefaultDirName={autopf}\pf
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog commandline
OutputDir=..\..\dist
OutputBaseFilename=pf-setup
Compression=lzma2
SolidCompression=yes
ChangesEnvironment=yes
InfoAfterFile=post_install_info.txt
; Unsigned for v1: first run will trigger a SmartScreen warning. Code-signing
; is a follow-up once a certificate is provisioned, not a blocker for this PR.

[Files]
Source: "..\..\dist\pf\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs

[Code]
function EnvironmentRoot: Integer;
begin
  if IsAdminInstallMode then
    Result := HKEY_LOCAL_MACHINE
  else
    Result := HKEY_CURRENT_USER;
end;

function EnvironmentKey: string;
begin
  if IsAdminInstallMode then
    Result := 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  else
    Result := 'Environment';
end;

procedure EnvAddPath(Path: string);
var
  Paths: string;
begin
  if not RegQueryStringValue(EnvironmentRoot, EnvironmentKey, 'Path', Paths) then
    Paths := '';
  if Paths = '' then
    Paths := Path
  else if Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(Paths) + ';') = 0 then
    Paths := Paths + ';' + Path;
  RegWriteExpandStringValue(EnvironmentRoot, EnvironmentKey, 'Path', Paths);
end;

procedure EnvRemovePath(Path: string);
var
  Paths: string;
  P: Integer;
begin
  if not RegQueryStringValue(EnvironmentRoot, EnvironmentKey, 'Path', Paths) then
    exit;
  P := Pos(';' + Uppercase(Path) + ';', ';' + Uppercase(Paths) + ';');
  if P = 0 then
    exit;
  Delete(Paths, P - 1, Length(Path) + 1);
  RegWriteExpandStringValue(EnvironmentRoot, EnvironmentKey, 'Path', Paths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    EnvAddPath(ExpandConstant('{app}'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    EnvRemovePath(ExpandConstant('{app}'));
end;
