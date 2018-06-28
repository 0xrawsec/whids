@echo off

set BASENAME=Whids.exe
set INSTALL_DIR=%programfiles%\Whids
set UNINSTALL_SCRIPT=%INSTALL_DIR%\uninstall.bat
set BINPATH=%INSTALL_DIR%\%BASENAME%
set VERSION="REPLACED BY MAKEFILE"
set DATABASEDIR=%INSTALL_DIR%\Database
set LOGDIR=%INSTALL_DIR%\Logs
set LOGFILE=%LOGDIR%\Whids.log
set ALERTDIR=%INSTALL_DIR%\Alerts
set ALERTFILE=%ALERTDIR%\Alerts.json.gz
set TN=Whids
set CMD=\"%BINPATH%\" -service -phenix -c all -u -update-dir \"%DATABASEDIR%\" -l \"%LOGFILE%\" -o \"%ALERTFILE%\"

mkdir "%INSTALL_DIR%"
mkdir "%LOGDIR%"
mkdir "%ALERTDIR%"


echo "[+] Installing %BASENAME% (%PROCESSOR_ARCHITECTURE%) in %INSTALL_DIR%"
if %PROCESSOR_ARCHITECTURE%==AMD64 (
    echo F | xcopy /Y /X "%~dp0whids-v%VERSION%-amd64.exe" "%BINPATH%"
) else (
    echo F | xcopy /Y /X "%~dp0whids-v%VERSION%-386.exe" "%BINPATH%"
)

echo "[+] Creating scheduled task to start Whids at boot"
schtasks.exe /Create /RU SYSTEM /TN %TN% /SC ONSTART /F /TR "%CMD%"

echo "[+] Running the task just created"
schtasks.exe /Run /TN %TN%

echo "[+] Generating Uninstall Script"
echo @echo off > "%UNINSTALL_SCRIPT%"
echo cd "%PROGRAMFILES%" >> "%UNINSTALL_SCRIPT%"
echo taskkill /F /IM %BASENAME% >> "%UNINSTALL_SCRIPT%"
echo schtasks.exe /End /TN %TN% >> "%UNINSTALL_SCRIPT%"
echo schtasks.exe /Delete /F /TN %TN% >> "%UNINSTALL_SCRIPT%"
echo timeout 2 >> "%UNINSTALL_SCRIPT%"
echo cmd /c rmdir /S /Q "%INSTALL_DIR%" >> "%UNINSTALL_SCRIPT%"

timeout 10