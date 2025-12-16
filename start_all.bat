@echo off
echo ========================================
echo    IntelliGuard Cyber Security System
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

REM Check if pip is available
pip --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: pip is not available
    echo Please ensure pip is installed with Python
    pause
    exit /b 1
)

echo [1/5] Checking Python installation...
python --version
echo.

echo [2/5] Installing/Updating dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    pause
    exit /b 1
)
echo.

echo [3/5] Installing backend dependencies...
cd backend
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: Failed to install backend dependencies
    cd ..
    pause
    exit /b 1
)
cd ..
echo.

echo [4/5] Setting up environment...
if not exist .env (
    echo Creating .env file from template...
    copy .env.example .env
    echo Please configure .env file with your settings
)

REM Create necessary directories
if not exist "logs" mkdir logs
if not exist "uploads" mkdir uploads
if not exist "temp" mkdir temp
if not exist "backend\ml_models\trained_models" mkdir backend\ml_models\trained_models

echo.
echo [5/5] Starting IntelliGuard System...
echo.
echo Starting backend API server...
echo Backend will be available at: http://localhost:8000
echo API Documentation: http://localhost:8000/docs
echo.

REM Start the backend server
cd backend
start "IntelliGuard Backend" cmd /k "python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

REM Wait a moment for backend to start
timeout /t 5 /nobreak >nul

cd ..

echo Backend API server started successfully!

echo.
echo ========================================
echo   IntelliGuard System Started!
echo ========================================
echo.
echo Services:
echo   Backend API: http://localhost:8000
echo   API Docs:    http://localhost:8000/docs
echo   Health:      http://localhost:8000/health
echo.
echo Press Ctrl+C in the backend window to stop the system
echo.

REM Keep this window open
echo Press any key to close this window...
pause >nul