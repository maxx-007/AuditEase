@echo off
REM Run AuditEase Backend API Server (Windows)

echo ==========================================
echo Starting AuditEase Backend API Server
echo ==========================================

REM Check if virtual environment exists
if not exist venv (
    echo [ERROR] Virtual environment not found!
    echo Please run setup_env.bat first.
    pause
    exit /b 1
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Check if port is provided as argument
if "%1"=="" (
    set PORT=8000
) else (
    set PORT=%1
)

echo [INFO] Starting server on port %PORT%...
echo [INFO] API will be available at http://localhost:%PORT%
echo [INFO] API Documentation: http://localhost:%PORT%/docs
echo.
echo Press Ctrl+C to stop the server
echo.

python main.py serve --port %PORT%

pause

