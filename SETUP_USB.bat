@echo off
TITLE SOC USB Setup - Hide Development Files
CLS

:: Get the current directory
SET CURRENT_DIR=%~dp0

ECHO ========================================================
ECHO   SOC PORTABLE FORENSIC UNIT - USB SETUP
ECHO ========================================================
ECHO.
ECHO This script will hide all development files and folders,
ECHO leaving only the analyst-facing launchers visible:
ECHO.
ECHO   [VISIBLE] START_INVESTIGATION.bat
ECHO   [VISIBLE] COLLECT_EVIDENCE.bat
ECHO   [VISIBLE] Evidence_* folders
ECHO.
ECHO All other files will be hidden (not deleted).
ECHO.
ECHO Press any key to continue, or CTRL+C to cancel...
PAUSE >nul

ECHO.
ECHO [*] Hiding development files and folders...

cd /d "%CURRENT_DIR%"

:: Hide Python and core folders
attrib +h +s "Python_Portable" 2>nul
attrib +h +s "core" 2>nul
attrib +h +s "tabs" 2>nul
attrib +h +s "components" 2>nul
attrib +h +s "config" 2>nul
attrib +h +s "docs" 2>nul
attrib +h +s "rules" 2>nul
attrib +h +s "tools" 2>nul
attrib +h +s "build" 2>nul
attrib +h +s "__pycache__" 2>nul

:: Hide development files
attrib +h "dashboard.py" 2>nul
attrib +h "collector.py" 2>nul
attrib +h "requirements.txt" 2>nul
attrib +h "README.md" 2>nul
attrib +h "LICENSE" 2>nul
attrib +h ".gitignore" 2>nul
attrib +h "INSTALL_DEPS.bat" 2>nul
attrib +h "nul" 2>nul

:: Hide this setup script itself
attrib +h "SETUP_USB.bat" 2>nul
attrib +h "UNHIDE_TOOLS.bat" 2>nul

ECHO.
ECHO [+] Done! The USB is now ready for analysts.
ECHO.
ECHO Visible files:
ECHO   - START_INVESTIGATION.bat
ECHO   - COLLECT_EVIDENCE.bat
ECHO   - Evidence_* folders (if present)
ECHO.
ECHO To unhide files later, run UNHIDE_TOOLS.bat (hidden in this folder)
ECHO or use: attrib -h -s * in Command Prompt
ECHO.
PAUSE
