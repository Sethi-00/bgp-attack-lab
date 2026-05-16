#!/bin/bash
# Quick setup script for dashboard
# Run: ./setup-dashboard.sh

set -e

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$REPO_ROOT"

echo "🚀 Setting up BGP Hijack Lab Dashboard..."
echo ""

# Install backend dependencies
echo "📦 Installing backend dependencies..."
pip install -q -r requirements.txt
echo "✓ Backend ready"

# Install frontend dependencies
echo "📦 Installing frontend dependencies..."
cd frontend
npm install --silent
cd ..
echo "✓ Frontend ready"

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p reports data

echo ""
echo "✅ Setup complete!"
echo ""
echo "To start the dashboard, run:"
echo "  ./start-dashboard.sh"
echo ""
echo "Or start services separately:"
echo "  Terminal 1: python3 -m src.api.server"
echo "  Terminal 2: cd frontend && npm run dev"
echo ""
echo "Then open: http://localhost:5173"
