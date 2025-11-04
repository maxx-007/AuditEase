#!/bin/bash
# Compliance AI - Quick Start Demo Script
# ========================================
# This script demonstrates the complete Compliance AI workflow

echo "========================================="
echo "Compliance AI - Quick Start Demo"
echo "========================================="
echo ""

# Check for virtual environment and activate if found (optional)
if [ -d "venv" ] && [ -f "venv/bin/activate" ]; then
    echo "ℹ️  Virtual environment detected. Consider activating it:"
    echo "   source venv/bin/activate"
    echo ""
elif [ -d "venv" ] && [ -f "venv/Scripts/activate" ]; then
    echo "ℹ️  Virtual environment detected (Windows). Consider activating it:"
    echo "   venv\\Scripts\\activate"
    echo ""
fi

# Use 'python' command (works on both Windows and Unix)
# Check if python exists and has pip
PYTHON_CMD=""
if command -v python &> /dev/null || type python &> /dev/null; then
    PYTHON_CMD="python"
elif command -v python3 &> /dev/null || type python3 &> /dev/null; then
    PYTHON_CMD="python3"
fi

if [ -z "$PYTHON_CMD" ]; then
    echo "❌ Python not found. Please install Python 3.7+"
    exit 1
fi

python_version=$($PYTHON_CMD --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $python_version"

# Check if dependencies are installed
if ! $PYTHON_CMD -c "import sklearn, pandas, numpy, joblib" 2>/dev/null; then
    echo "❌ Missing dependencies. Installing..."
    
    # Check if pip is available (with better error handling)
    if ! $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
        echo "⚠️  pip check failed for $PYTHON_CMD. Trying to bootstrap pip..."
        # Try to install pip using ensurepip
        if $PYTHON_CMD -m ensurepip --upgrade >/dev/null 2>&1; then
            echo "✓ pip installed successfully"
        else
            echo "❌ Failed to install pip automatically."
            echo ""
            echo "Please install pip manually using:"
            echo "   python -m ensurepip --upgrade"
            echo ""
            echo "Then run this script again."
            exit 1
        fi
    fi
    
    # Verify pip is now working
    if ! $PYTHON_CMD -m pip --version >/dev/null 2>&1; then
        echo "❌ pip is still not available. Please install it manually."
        exit 1
    fi
    
    echo "✓ pip is available"
    
    # Install dependencies
    echo "Installing dependencies from requirements.txt..."
    if ! $PYTHON_CMD -m pip install -r requirements.txt; then
        echo "❌ Failed to install dependencies. Please check requirements.txt and install manually."
        exit 1
    fi
fi
echo "✓ Dependencies installed"
echo ""

# Step 1: Train Model
echo "========================================="
echo "Step 1: Training Compliance Model"
echo "========================================="
echo ""

if [ -f "datasets/example_training_data.json" ]; then
    echo "Training model with example dataset..."
    $PYTHON_CMD compliance_ai.py train \
        --data datasets/example_training_data.json \
        --out models/ \
        --model-name demo_model \
        --model-type rf
    echo ""
    echo "✓ Model trained successfully!"
else
    echo "❌ Example dataset not found. Please ensure datasets/example_training_data.json exists."
    exit 1
fi

echo ""
sleep 2

# Step 2: Collect Data
echo "========================================="
echo "Step 2: Collecting Compliance Data"
echo "========================================="
echo ""

echo "Collecting compliance data from current system..."
$PYTHON_CMD compliance_ai.py collect \
    --source live_system \
    --out outputs/demo_snapshot.json \
    --company-name "Demo Company" \
    --company-type "Technology"
echo ""
echo "✓ Data collected successfully!"

echo ""
sleep 2

# Step 3: Run Inference
echo "========================================="
echo "Step 3: Running Compliance Inference"
echo "========================================="
echo ""

echo "Analyzing compliance posture..."
$PYTHON_CMD compliance_ai.py infer \
    --model models/demo_model.joblib \
    --data outputs/demo_snapshot.json \
    --out outputs/demo_results.json \
    --format both \
    --detailed
echo ""
echo "✓ Inference complete!"

echo ""
sleep 1

# Display Results
echo "========================================="
echo "Demo Complete!"
echo "========================================="
echo ""
echo "Generated Files:"
echo "  📊 Model:           models/demo_model.joblib"
echo "  📝 Training Summary: models/demo_model_summary.json"
echo "  💾 Snapshot:        outputs/demo_snapshot.json"
echo "  📈 Results (JSON):  outputs/demo_results.json"
echo "  📄 Report (Text):   outputs/demo_results_report.txt"
echo ""

# Show text report if exists
if [ -f "outputs/demo_results_report.txt" ]; then
    echo "========================================="
    echo "Compliance Assessment Report Preview"
    echo "========================================="
    head -n 30 outputs/demo_results_report.txt
    echo ""
    echo "... (see full report in outputs/demo_results_report.txt)"
fi

echo ""
echo "========================================="
echo "Next Steps:"
echo "========================================="
echo ""
echo "1. View detailed report:"
echo "   cat outputs/demo_results_report.txt"
echo ""
echo "2. Check JSON results:"
echo "   cat outputs/demo_results.json | jq"
echo ""
echo "3. Retrain with your data:"
echo "   $PYTHON_CMD compliance_ai.py train --data your_data/ --model-name production_model"
echo ""
echo "4. Set up continuous monitoring:"
echo "   $PYTHON_CMD compliance_ai.py collect --realtime --interval 300"
echo ""
echo "5. Read full documentation:"
echo "   cat README.md"
echo "   cat USAGE_GUIDE.md"
echo ""
echo "========================================="
echo "Thank you for using Compliance AI!"
echo "=========================================" 