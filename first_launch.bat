@echo off
title Behavioral_Sentinel_Active Master Launcher
echo Initializing Security Hub...

:: 1. Start the Database & API in the background (minimized)
echo Launching Backend...
start /min cmd /k "python first_database_api.py"

:: Wait 3 seconds for the API to start up
timeout /t 3 /nobreak > nul

:: 2. Start the Monitoring Agent in the background (minimized)
echo Launching Monitoring Agent...
start /min cmd /k "python first.py"

:: 3. Start the GUI in the main window
echo Launching GUI...
python first_gui.py

echo.
echo All components stopped.
pause