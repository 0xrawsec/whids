@echo off

set BASENAME=Whids.exe
set INSTALL_DIR=%programfiles%\Whids
set UNINSTALL_SCRIPT=%INSTALL_DIR%\Uninstall.bat
set BINPATH=%INSTALL_DIR%\%BASENAME%
set CONFIG=%INSTALL_DIR%\config.toml
REM default during installation used to clean
set LOGS=%INSTALL_DIR%\Logs
set ALERTS=%INSTALL_DIR%\Logs\Alerts
set DUMPS=%INSTALL_DIR%\Dumps
set VERSION="REPLACED BY MAKEFILE"
set COMMITID="REPLACED BY MAKEFILE"
set SVC=Whids

set RULES_IMPORT="%~dp0\rules"

:choice
echo  [i]  Install WHIDS from scratch (removes older installation)
echo [un]  Uninstall previous installation
echo [up]  Update WHIDS binary and rules (keeps current config)
echo [st]  Start service
echo [sp]  Stop service
echo  [d]  Disable service
echo  [r]  Restart service
echo  [g]  Remove alerts logs and dumps
echo  [e]  Edit WHIDS configuration with a registered application
echo [en]  Edit WHIDS configuration with notepad
echo  [c]  Clear screen
echo  [q]  Quit
echo.

echo Whids version: %VERSION% (commit: %COMMITID%)
SET /P _in= "Please select option (can be combined with +):"
SET _in_ch="%_in%"


:FORLOOP
FOR /F "tokens=1* delims=+" %%A IN (%_in_ch%) DO (
    
    IF "%%A"=="i" (
        call :StopSvcs
        call :Uninstall
        call :Install
        call :CreateWhidsSvc
        call :ImportRules
        call :GenUninstall
        call :PromptStartSvcs
    )
    IF "%%A"=="un" (
        call :Uninstall
    )
    IF "%%A"=="up" (
        call :StopSvcs
        call :CopyBin
        call :ImportRules
        call :PromptStartSvcs
    )
    IF "%%A"=="st" (
        call :StartSvcs
    )
    IF "%%A"=="sp" (
        call :StopSvcs
    )
    IF "%%A"=="d" (
        call :DisableSvc
    )
    IF "%%A"=="r" (
        call :StopSvcs
        call :StartSvcs
    )
    IF "%%A"=="g" (
        call :Groom
    )
    IF "%%A"=="e" (
        start "" "%CONFIG%"
        cls
    )
    IF "%%A"=="en" (
        notepad "%CONFIG%"
        cls
    )
    IF "%%A"=="c" (
        cls
    )
    IF "%%A"=="q" (
        EXIT 0
    )

    set _in_ch="%%B"
    if NOT %_in_ch%=="" goto FORLOOP

)

echo.
GOTO :choice

:Groom
IF exist "%LOGS%" (
    echo.
    echo [+] Removing directory: "%LOGS%"
    rmdir /S /Q "%LOGS%"
)

IF exist "%DUMPS%" (
    echo [+] Removing directory: "%DUMPS%"
    rmdir /S /Q "%DUMPS%"
    echo.
)
EXIT /B 0

:Uninstall
echo.
IF exist "%UNINSTALL_SCRIPT%" (
    echo [+] Running uninstallation script
    cmd /c "%UNINSTALL_SCRIPT%"
    echo [+] Uninstallation finished
)
EXIT /B 0

:CopyBin
echo [+] Installing %BASENAME% (%PROCESSOR_ARCHITECTURE%) in %INSTALL_DIR%
if %PROCESSOR_ARCHITECTURE%==AMD64 (
    echo F | xcopy /Y /X "%~dp0whids-v%VERSION%-amd64.exe" "%BINPATH%"
) else (
    echo F | xcopy /Y /X "%~dp0whids-v%VERSION%-386.exe" "%BINPATH%"
)
EXIT /B 0

:Install
echo.
echo [+] Creating Installation Directory: %INSTALL_DIR%
mkdir "%INSTALL_DIR%"

call :CopyBin

echo [+] Setting up rights to installation directory
icacls "%INSTALL_DIR%" /inheritance:r /grant:r Administrators:(OI)(CI)F /grant:r SYSTEM:(OI)(CI)F

echo [+] Installing
"%BINPATH%" -install
EXIT /B 0

:ImportRules
:ask_import
echo.
SET /P _input= "[+] Do you want to import detection rules shipped with project [Y/N]:"
IF "%_input%"=="Y" GOTO :import
IF "%_input%"=="N" GOTO :end_import
GOTO :ask_import
:import
"%BINPATH%" -import "%RULES_IMPORT%"
:end_import
EXIT /B 0

:CreateWhidsSvc
echo.
echo [+] Creating WHIDS service
sc.exe create %SVC% binPath= "%BINPATH%" start= auto
sc.exe description %SVC% "Windows Host IDS (v%VERSION%)"
sc.exe failure whids reset= 0 actions= restart/0

EXIT /B 0

:GenUninstall 
echo.
echo [+] Generating Uninstall Script
echo @echo off > "%UNINSTALL_SCRIPT%"
echo "%BINPATH%" -uninstall >> "%UNINSTALL_SCRIPT%"
echo cd "%PROGRAMFILES%" >> "%UNINSTALL_SCRIPT%"
echo net.exe stop %SVC% /yes >> "%UNINSTALL_SCRIPT%"
echo sc.exe delete %SVC% >> "%UNINSTALL_SCRIPT%"
echo timeout 10 >> "%UNINSTALL_SCRIPT%"
echo cmd /c rmdir /S /Q "%INSTALL_DIR%" >> "%UNINSTALL_SCRIPT%"
EXIT /B 0

:StartSvcs
echo.
echo [+] Running %SVC% service
sc.exe config %SVC% start= auto
net.exe start %SVC%
EXIT /B 0

:PromptStartSvcs
echo.
:ask_start
SET /P _input= "[+] Do you want to start service [Y/N]:"
IF "%_input%"=="Y" GOTO :start
IF "%_input%"=="N" GOTO :end_start
GOTO :ask_start
:start
call :StartSvcs
:end_start
EXIT /B 0

:StopSvcs
echo.
echo [+] Stopping %SVC% service
net.exe stop %SVC% /yes
EXIT /B 0

:DisableSvc
echo.
echo [+] Disabling %SVC% service
net.exe stop %SVC% /yes
:: we might need this in case the service is crashing and restarting constently
sc.exe config %SVC% start= disabled
EXIT /B 0