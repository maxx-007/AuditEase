#!/bin/bash
# Run AuditEase Backend API Server

echo "=========================================="
echo "Starting AuditEase Backend API Server"
echo "=========================================="

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found!"
    echo "Please run setup_env.sh first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Get port from argument or use default
PORT=${1:-8000}

echo "🚀 Starting server on port $PORT..."
echo "📡 API will be available at http://localhost:$PORT"
echo "📚 API Documentation: http://localhost:$PORT/docs"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

python main.py serve --port $PORT

