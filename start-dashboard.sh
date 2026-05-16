#!/bin/bash
# BGP Hijack Lab Dashboard - Unified Launcher
# Starts both backend and frontend with proper logging

set -e

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cd "$REPO_ROOT"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  BGP Hijack Lab Dashboard - Unified Launcher      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════╝${NC}\n"

# Check for required commands
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}✗ $1 not found. Please install it first.${NC}"
        exit 1
    fi
}

echo -e "${YELLOW}[1/4]${NC} Checking dependencies..."
check_command "python3"
check_command "node"
check_command "npm"
echo -e "${GREEN}✓ All dependencies found${NC}\n"

# Check Python version
PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if [[ ! "$PYTHON_VERSION" > "3.7" ]]; then
    echo -e "${RED}✗ Python 3.8+ required (found $PYTHON_VERSION)${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Python $PYTHON_VERSION${NC}\n"

# Check if frontend node_modules exist
echo -e "${YELLOW}[2/4]${NC} Setting up frontend..."
if [ ! -d "frontend/node_modules" ]; then
    echo -e "${YELLOW}Installing frontend dependencies...${NC}"
    cd frontend
    npm install --silent > /dev/null 2>&1 &
    FRONTEND_INSTALL_PID=$!
    cd ..
else
    echo -e "${GREEN}✓ Frontend dependencies already installed${NC}"
fi

# Check if backend can start
echo -e "${YELLOW}[3/4]${NC} Checking backend..."
if python3 -c "import fastapi, uvicorn" 2>/dev/null; then
    echo -e "${GREEN}✓ Backend dependencies ready${NC}"
else
    echo -e "${YELLOW}Installing backend dependencies...${NC}"
    pip install -q fastapi uvicorn python-multipart
    echo -e "${GREEN}✓ Backend dependencies installed${NC}"
fi

# Wait for frontend install if it's running
if [ ! -z "$FRONTEND_INSTALL_PID" ]; then
    wait $FRONTEND_INSTALL_PID
    echo -e "${GREEN}✓ Frontend dependencies installed${NC}"
fi

echo -e "${YELLOW}[4/4]${NC} Starting services...\n"

# Create temp directory for logs
LOG_DIR=$(mktemp -d)
BACKEND_LOG="$LOG_DIR/backend.log"
FRONTEND_LOG="$LOG_DIR/frontend.log"

echo -e "${BLUE}Starting Backend API Server...${NC}"
echo "PYTHONPATH=. python3 -m src.api.server" > "$BACKEND_LOG"
PYTHONPATH=. python3 -m src.api.server >> "$BACKEND_LOG" 2>&1 &
BACKEND_PID=$!
echo -e "${GREEN}✓ Backend PID: $BACKEND_PID${NC}"
echo "  Log: $BACKEND_LOG"

# Wait for backend to start
echo -e "\n${YELLOW}Waiting for backend to initialize...${NC}"
for i in {1..30}; do
    if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Backend ready at http://localhost:8000${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}✗ Backend failed to start${NC}"
        kill $BACKEND_PID 2>/dev/null || true
        exit 1
    fi
    echo -n "."
    sleep 0.5
done

# Start frontend
echo -e "\n${BLUE}Starting Frontend Dev Server...${NC}"
cd frontend
npm run dev >> "$FRONTEND_LOG" 2>&1 &
FRONTEND_PID=$!
cd ..
echo -e "${GREEN}✓ Frontend PID: $FRONTEND_PID${NC}"
echo "  Log: $FRONTEND_LOG"

# Display success message
echo -e "\n${GREEN}╔════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          Dashboard is ready!                       ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════╝${NC}\n"

echo -e "${BLUE}Service URLs:${NC}"
echo -e "  ${GREEN}Dashboard:${NC}    http://localhost:5173"
echo -e "  ${GREEN}API Server:${NC}   http://localhost:8000"
echo -e "  ${GREEN}API Docs:${NC}     http://localhost:8000/docs"
echo -e "  ${GREEN}ReDoc:${NC}        http://localhost:8000/redoc"

echo -e "\n${BLUE}Process IDs:${NC}"
echo -e "  Backend:  $BACKEND_PID"
echo -e "  Frontend: $FRONTEND_PID"

echo -e "\n${YELLOW}To stop services, press Ctrl+C${NC}\n"

# Function to cleanup on exit
cleanup() {
    echo -e "\n${YELLOW}Shutting down services...${NC}"
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    wait $BACKEND_PID 2>/dev/null || true
    wait $FRONTEND_PID 2>/dev/null || true
    echo -e "${GREEN}✓ All services stopped${NC}"
    echo -e "${YELLOW}Logs saved to: $LOG_DIR${NC}"
}

trap cleanup EXIT

# Keep script running
wait
