#!/bin/bash

# IntelliGuard Startup Script for Linux/macOS
# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================"
echo -e "   IntelliGuard Cyber Security System"
echo -e "========================================${NC}"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    if ! command -v python &> /dev/null; then
        echo -e "${RED}ERROR: Python is not installed${NC}"
        echo "Please install Python 3.8+ from https://python.org"
        exit 1
    else
        PYTHON_CMD="python"
    fi
else
    PYTHON_CMD="python3"
fi

# Check if pip is available
if ! command -v pip3 &> /dev/null; then
    if ! command -v pip &> /dev/null; then
        echo -e "${RED}ERROR: pip is not available${NC}"
        echo "Please ensure pip is installed with Python"
        exit 1
    else
        PIP_CMD="pip"
    fi
else
    PIP_CMD="pip3"
fi

echo -e "${GREEN}[1/5] Checking Python installation...${NC}"
$PYTHON_CMD --version
echo

echo -e "${GREEN}[2/5] Installing/Updating dependencies...${NC}"
$PIP_CMD install -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to install dependencies${NC}"
    exit 1
fi
echo

echo -e "${GREEN}[3/5] Installing backend dependencies...${NC}"
cd backend
$PIP_CMD install -r requirements.txt
if [ $? -ne 0 ]; then
    echo -e "${RED}ERROR: Failed to install backend dependencies${NC}"
    cd ..
    exit 1
fi
cd ..
echo

echo -e "${GREEN}[4/5] Setting up environment...${NC}"
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo -e "${YELLOW}Please configure .env file with your settings${NC}"
fi

# Create necessary directories
mkdir -p logs uploads temp backend/ml_models/trained_models

echo
echo -e "${GREEN}[5/5] Starting IntelliGuard System...${NC}"
echo
echo "Starting backend API server..."
echo -e "${BLUE}Backend will be available at: http://localhost:8000${NC}"
echo -e "${BLUE}API Documentation: http://localhost:8000/docs${NC}"
echo

# Start the backend server in background
cd backend
$PYTHON_CMD -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!

# Wait a moment for backend to start
sleep 5

cd ..

echo
echo "Starting frontend dashboard..."
echo -e "${BLUE}Frontend will be available at: http://localhost:3001${NC}"
echo

# Start simple HTTP server for frontend
cd frontend
$PYTHON_CMD -m http.server 3001 &
FRONTEND_PID=$!
cd ..

echo -e "${GREEN}Backend API server and frontend dashboard started successfully!${NC}"

echo
echo -e "${GREEN}========================================"
echo -e "   IntelliGuard System Started!"
echo -e "========================================${NC}"
echo
echo "Services:"
echo -e "  ${BLUE}Backend API: http://localhost:8000${NC}"
echo -e "  ${BLUE}API Docs:    http://localhost:8000/docs${NC}"
echo -e "  ${BLUE}Health:      http://localhost:8000/health${NC}"
echo -e "  ${BLUE}Dashboard:   http://localhost:3001${NC}"
echo
echo -e "${YELLOW}Press Ctrl+C to stop the system${NC}"
echo

# Function to cleanup on exit
cleanup() {
    echo
    echo -e "${YELLOW}Stopping IntelliGuard System...${NC}"
    if [ ! -z "$BACKEND_PID" ]; then
        kill $BACKEND_PID 2>/dev/null
    fi
    if [ ! -z "$FRONTEND_PID" ]; then
        kill $FRONTEND_PID 2>/dev/null
    fi
    echo -e "${GREEN}System stopped.${NC}"
    exit 0
}

# Trap Ctrl+C
trap cleanup SIGINT

# Wait for processes
wait