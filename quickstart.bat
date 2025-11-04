@echo off
REM Compliance AI - Quick Start Demo Script (Windows)
REM ================================================
REM This script demonstrates the complete Compliance AI workflow

echo =========================================
echo Compliance AI - Quick Start Demo
echo =========================================
echo.

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found. Please install Python 3.7+
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo ✓ Python version: %PYTHON_VERSION%

REM Check if dependencies are installed
python -c "import sklearn, pandas, numpy, joblib" >nul 2>&1
if errorlevel 1 (
    echo ❌ Missing dependencies. Installing...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo ❌ Failed to install dependencies
        exit /b 1
    )
)
echo ✓ Dependencies installed
echo.

REM Step 1: Train Model
echo =========================================
echo Step 1: Training Compliance Model
echo =========================================
echo.

if exist "datasets\example_training_data.json" (
    echo Training model with example dataset...
    python compliance_ai.py train --data datasets\example_training_data.json --out models\ --model-name demo_model --model-type rf
    if errorlevel 1 (
        echo ❌ Training failed
        exit /b 1
    )
    echo.
    echo ✓ Model trained successfully!
) else (
    echo ❌ Example dataset not found. Please ensure datasets\example_training_data.json exists.
    exit /b 1
)

echo.
timeout /t 2 /nobreak >nul

REM Step 2: Collect Data
echo =========================================
echo Step 2: Collecting Compliance Data
echo =========================================
echo.

echo Collecting compliance data from current system...
python compliance_ai.py collect --source live_system --out outputs\demo_snapshot.json --company-name "Demo Company" --company-type "Technology"
if errorlevel 1 (
    echo ❌ Data collection failed
    exit /b 1
)
echo.
echo ✓ Data collected successfully!

echo.
timeout /t 2 /nobreak >nul

REM Step 3: Run Inference
echo =========================================
echo Step 3: Running Compliance Inference
echo =========================================
echo.

echo Analyzing compliance posture...
python compliance_ai.py infer --model models\demo_model.joblib --data outputs\demo_snapshot.json --out outputs\demo_results.json --format both --detailed
if errorlevel 1 (
    echo ❌ Inference failed
    exit /b 1
)
echo.
echo ✓ Inference complete!

echo.
timeout /t 1 /nobreak >nul

REM Display Results
echo =========================================
echo Demo Complete!
echo =========================================
echo.
echo Generated Files:
echo   📊 Model:           models\demo_model.joblib
echo   📝 Training Summary: models\demo_model_summary.json
echo   💾 Snapshot:        outputs\demo_snapshot.json
echo   📈 Results (JSON):  outputs\demo_results.json
echo   📄 Report (Text):   outputs\demo_results_report.txt
echo.

REM Show text report if exists
if exist "outputs\demo_results_report.txt" (
    echo =========================================
    echo Compliance Assessment Report Preview
    echo =========================================
    powershell -Command "Get-Content outputs\demo_results_report.txt -TotalCount 30"
    echo.
    echo ... (see full report in outputs\demo_results_report.txt)
)

echo.
echo =========================================
echo Next Steps:
echo =========================================
echo.
echo 1. View detailed report:
echo    type outputs\demo_results_report.txt
echo.
echo 2. Check JSON results:
echo    type outputs\demo_results.json
echo.
echo 3. Retrain with your data:
echo    python compliance_ai.py train --data your_data\ --model-name production_model
echo.
echo 4. Set up continuous monitoring:
echo    python compliance_ai.py collect --realtime --interval 300
echo.
echo 5. Read full documentation:
echo    type README.md
echo    type USAGE_GUIDE.md
echo.
echo =========================================
echo Thank you for using Compliance AI!
echo =========================================

