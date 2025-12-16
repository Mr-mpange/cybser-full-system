@echo off
echo ========================================
echo    Stopping IntelliGuard System
echo ========================================
echo.

echo Stopping backend processes...
taskkill /f /im python.exe /t 2>nul
taskkill /f /im uvicorn.exe /t 2>nul

echo Stopping frontend processes...
taskkill /f /im node.exe /t 2>nul
taskkill /f /im npm.exe /t 2>nul

echo.
echo IntelliGuard system stopped.
echo.
pause