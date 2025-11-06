@echo off
REM Setup Python Virtual Environment for AuditEase Backend (Windows)

echo ==========================================
echo AuditEase Backend - Environment Setup
echo ==========================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed. Please install Python 3.8 or higher.
    exit /b 1
)

REM Get Python version
for /f "tokens=2" %%i in ('python --version') do set PYTHON_VERSION=%%i
echo [OK] Found Python %PYTHON_VERSION%

REM Create virtual environment
if exist venv (
    echo [WARN] Virtual environment already exists. Removing old one...
    rmdir /s /q venv
)

echo [INFO] Creating virtual environment...
python -m venv venv

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo [INFO] Upgrading pip...
python -m pip install --upgrade pip

REM Install requirements
echo [INFO] Installing dependencies...
pip install -r requirements.txt

echo.
echo ==========================================
echo [SUCCESS] Setup Complete!
echo ==========================================
echo.
echo To activate the virtual environment, run:
echo   venv\Scripts\activate.bat
echo.
echo To start the API server, run:
echo   python main.py serve --port 8000
echo.
echo To deactivate, run:
echo   deactivate
echo.

pause

