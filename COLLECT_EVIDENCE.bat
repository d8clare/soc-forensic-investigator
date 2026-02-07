@echo off
:: Request Administrator Privileges
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo [!] Requesting Administrator privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

TITLE SOC Evidence Collector [Administrator]
CLS

:: Get the current directory where this script is located
SET CURRENT_DIR=%~dp0

:: Path to portable Python
SET PYTHON_EXE="%CURRENT_DIR%Python_Portable\python.exe"

ECHO ========================================================
ECHO   SOC PORTABLE FORENSIC UNIT - EVIDENCE COLLECTOR
ECHO ========================================================
ECHO.
ECHO [+] Running as Administrator
ECHO [*] Running from: %CURRENT_DIR%
ECHO [*] Using Portable Python engine...
ECHO.
ECHO [!] This will collect forensic evidence from this machine.
ECHO.
ECHO Press any key to start collection, or close window to cancel...
PAUSE >nul

ECHO.
ECHO [*] Starting evidence collection...
ECHO.

:: Run the collector
cd /d "%CURRENT_DIR%"
%PYTHON_EXE% "%CURRENT_DIR%collector.py"

IF %ERRORLEVEL% EQU 0 (
    ECHO.
    ECHO ========================================================
    ECHO   COLLECTION COMPLETE
    ECHO ========================================================
    ECHO.
    ECHO [+] Evidence has been saved to the Evidence_* folder.
    ECHO [+] You can now run START_INVESTIGATION.bat to analyze.
    ECHO.
) ELSE (
    ECHO.
    ECHO [X] Error during collection. Check for errors above.
    ECHO.
)

PAUSE
