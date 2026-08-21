@echo off
if not "%~1"=="--version" exit /b 64
echo codex-cli 1.1
type "C:\ProgramData\Keeper\AuthorityService\config\provider-identity.bin" >nul 2>&1
if errorlevel 1 (
  echo protected-read=denied
) else (
  echo protected-read=allowed
)
exit /b 0
