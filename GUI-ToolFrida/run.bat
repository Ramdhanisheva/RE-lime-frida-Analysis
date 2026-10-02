@echo off
title Frida Android CTF Assistant - HackToday 2026
cd /d "%~dp0"

echo ========================================================
echo   FRIDA ANDROID CTF ASSISTANT - GUI LAUNCHER
echo ========================================================
echo Membuka aplikasi GUI...

python main.py
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Terjadi kendala saat membuka aplikasi GUI.
    echo Mencoba dengan python3...
    python3 main.py
    pause
)
