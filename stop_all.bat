@echo off
echo ========================================
echo    Stopping IntelliGuard System
echo ========================================
echo.

echo Stopping backend processes...
taskkill /f /im python.exe /t 2>nul
taskkill /f /im uvicorn.exe /t 2>nul

echo Stopping frontend dashboard...
taskkill /f /im python.exe /fi "WINDOWTITLE eq IntelliGuard Dashboard*" 2>nul

echo.
echo All IntelliGuard processes stopped.

echo.
echo IntelliGuard system stopped.
echo.
pause