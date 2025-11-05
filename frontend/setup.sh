#!/bin/bash

# Compliance AI Engine - Frontend Setup Script
# This script automates the complete setup process

echo "🛡️  Compliance AI Engine - Frontend Setup"
echo "=========================================="
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js v16 or higher."
    echo "   Visit: https://nodejs.org/"
    exit 1
fi

echo "✅ Node.js version: $(node --version)"
echo "✅ npm version: $(npm --version)"
echo ""

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ package.json not found. Please run this script from the project root."
    exit 1
fi

echo "📦 Installing dependencies..."
npm install

if [ $? -ne 0 ]; then
    echo "❌ Failed to install dependencies"
    exit 1
fi

echo ""
echo "✅ Dependencies installed successfully!"
echo ""

# Create .env file if it doesn't exist
if [ ! -f ".env" ]; then
    echo "📝 Creating .env file..."
    cp .env.example .env
    echo "✅ .env file created. Please edit it with your backend URL."
else
    echo "ℹ️  .env file already exists."
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit .env file and set your backend URL:"
echo "   VITE_API_BASE_URL=http://localhost:8000"
echo ""
echo "2. Make sure your backend is running"
echo ""
echo "3. Start the development server:"
echo "   npm run dev"
echo ""
echo "4. Build for production:"
echo "   npm run build"
echo ""
echo "Happy coding! 🚀"