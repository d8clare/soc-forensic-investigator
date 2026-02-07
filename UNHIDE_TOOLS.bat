@echo off
TITLE SOC USB Setup - Unhide Development Files
CLS

:: Get the current directory
SET CURRENT_DIR=%~dp0

ECHO ========================================================
ECHO   SOC PORTABLE FORENSIC UNIT - UNHIDE TOOLS
ECHO ========================================================
ECHO.
ECHO This script will restore visibility of all hidden files.
ECHO.
ECHO Press any key to continue...
PAUSE >nul

ECHO.
ECHO [*] Unhiding all files and folders...

cd /d "%CURRENT_DIR%"

:: Unhide Python and core folders
attrib -h -s "Python_Portable" 2>nul
attrib -h -s "core" 2>nul
attrib -h -s "tabs" 2>nul
attrib -h -s "components" 2>nul
attrib -h -s "config" 2>nul
attrib -h -s "docs" 2>nul
attrib -h -s "rules" 2>nul
attrib -h -s "tools" 2>nul
attrib -h -s "build" 2>nul
attrib -h -s "__pycache__" 2>nul

:: Unhide development files
attrib -h "dashboard.py" 2>nul
attrib -h "collector.py" 2>nul
attrib -h "requirements.txt" 2>nul
attrib -h "README.md" 2>nul
attrib -h "LICENSE" 2>nul
attrib -h ".gitignore" 2>nul
attrib -h "INSTALL_DEPS.bat" 2>nul
attrib -h "SETUP_USB.bat" 2>nul
attrib -h "UNHIDE_TOOLS.bat" 2>nul
attrib -h "nul" 2>nul

ECHO.
ECHO [+] Done! All development files are now visible.
ECHO.
PAUSE
