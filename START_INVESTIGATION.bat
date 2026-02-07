@echo off
TITLE SOC Forensic Dashboard
CLS

:: מזהה את התיקייה הנוכחית שבה נמצא הסקריפט
SET CURRENT_DIR=%~dp0

:: מגדיר את הנתיב לפייתון הנייד שנמצא בתוך ה-USB
SET PYTHON_EXE="%CURRENT_DIR%Python_Portable\python.exe"

ECHO ========================================================
ECHO   SOC PORTABLE FORENSIC UNIT
ECHO ========================================================
ECHO.
ECHO [*] Running from: %CURRENT_DIR%
ECHO [*] Using Portable Python engine...
ECHO.

:: הרצת הדשבורד דרך הפייתון הנייד
cd /d "%CURRENT_DIR%"
%PYTHON_EXE% -m streamlit run "%CURRENT_DIR%dashboard.py"

IF %ERRORLEVEL% NEQ 0 (
    ECHO.
    ECHO [X] Error! Could not start the dashboard.
    PAUSE
)