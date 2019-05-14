@echo off

set BASENAME=Whids.exe
set INSTALL_DIR=%programfiles%\Whids
set START_SCRIPT=%INSTALL_DIR%\Start.bat
set STOP_SCRIPT=%INSTALL_DIR%\Stop.bat
set UNINSTALL_SCRIPT=%INSTALL_DIR%\Uninstall.bat
set BINPATH=%INSTALL_DIR%\%BASENAME%
set VERSION="REPLACED BY MAKEFILE"
set TN=Whids
set OPTIONS=-service -z
set CMD="%BINPATH%" %OPTIONS%
set LAUNCHER=%INSTALL_DIR%\Whids-launcher.bat

set RULES_IMPORT="%~dp0\rules"

echo [+] Creating Installation Directory: %INSTALL_DIR%
mkdir "%INSTALL_DIR%"

echo [+] Installing %BASENAME% (%PROCESSOR_ARCHITECTURE%) in %INSTALL_DIR%
if %PROCESSOR_ARCHITECTURE%==AMD64 (
    echo F | xcopy /Y /X "%~dp0whids-v%VERSION%-amd64.exe" "%BINPATH%"
) else (
    echo F | xcopy /Y /X "%~dp0whids-v%VERSION%-386.exe" "%BINPATH%"
)

echo [+] Setting up writes to installation directory
icacls "%INSTALL_DIR%" /inheritance:r /grant:r Administrators:(OI)(CI)F /grant:r SYSTEM:(OI)(CI)F

echo [+] Installing default configuration file
"%BINPATH%" -dump-conf > "%INSTALL_DIR%\config.json"

:ask_import
echo.
SET /P _input= "[+] Do you want to import detection rules shipped with project [Y/N]:"
IF "%_input%"=="Y" GOTO :import
IF "%_input%"=="N" GOTO :end
GOTO :ask_import
:import
"%BINPATH%" -import "%RULES_IMPORT%"
:end

echo [+] Creating scheduled task to start Whids at boot
echo %CMD% > "%LAUNCHER%"
schtasks.exe /Create /RU SYSTEM /TN %TN% /SC ONSTART /F /TR "\"%LAUNCHER%\""

REM Prefered way is to run Start.bat once config.json is fixed
REM echo "[+] Running the task just created"
REM schtasks.exe /Run /TN %TN%

echo [+] Generating Start Script
echo @echo off > "%START_SCRIPT%"
echo schtasks.exe /Run /TN %TN% >> "%START_SCRIPT%"
echo timeout 10 >> "%START_SCRIPT%"

echo [+] Generating Stop Script
echo @echo off > "%STOP_SCRIPT%"
echo taskkill /F /IM %BASENAME% >> "%STOP_SCRIPT%"
echo schtasks.exe /End /TN %TN% >> "%STOP_SCRIPT%"
echo timeout 10 >> "%STOP_SCRIPT%"

echo [+] Generating Uninstall Script
echo @echo off > "%UNINSTALL_SCRIPT%"
echo cd "%PROGRAMFILES%" >> "%UNINSTALL_SCRIPT%"
echo taskkill /F /IM %BASENAME% >> "%UNINSTALL_SCRIPT%"
echo schtasks.exe /End /TN %TN% >> "%UNINSTALL_SCRIPT%"
echo schtasks.exe /Delete /F /TN %TN% >> "%UNINSTALL_SCRIPT%"
echo timeout 10 >> "%UNINSTALL_SCRIPT%"
echo cmd /c rmdir /S /Q "%INSTALL_DIR%" >> "%UNINSTALL_SCRIPT%"

:ask_start
echo.
SET /P _input= "[+] Do you want to start WHIDS now [Y/N]:"
IF "%_input%"=="Y" GOTO :start
IF "%_input%"=="N" GOTO :end
GOTO :ask_start
:start
echo [+] Running the task just created
schtasks.exe /Run /TN %TN%
:end

timeout 60