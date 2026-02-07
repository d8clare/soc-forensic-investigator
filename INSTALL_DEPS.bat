@echo off
TITLE Installing Portable Dependencies
CLS

:: Get the directory where this script is located
SET SCRIPT_DIR=%~dp0
SET PYTHON_EXE="%SCRIPT_DIR%Python_Portable\python.exe"

cd /d "%SCRIPT_DIR%"

echo [1/3] Installing PIP management tool...
%PYTHON_EXE% get-pip.py

echo.
echo [2/3] Installing Streamlit and Pandas (This will take a minute)...
%PYTHON_EXE% -m pip install streamlit pandas

echo.
echo [3/3] Cleaning up...
del get-pip.py

echo.
echo [V] SUCCESS! Your portable Python is ready.
pause