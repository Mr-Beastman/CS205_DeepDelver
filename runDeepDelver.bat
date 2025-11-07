@echo off
title Launch DeepDelver GUI
setlocal enabledelayedexpansion

echo === Staring DeepDelver GUI === 

REM Check for and create virtual enviroment if needed
echo ^> Checking for virtual environment
if not exist venv (
    echo > No virtual enviroment found, creating venv 
    python -m venv venv
)

REM activate the virutal enviorment
echo ^> Activating venv
call venv\Scripts\activate

REM ensure requiremetns installed
echo ^> checking for requried dependencies
if exist requirements.txt (
    echo ^> Installing dependencies from requirements.txt
    pip install --upgrade pip >nul
    pip install -r requirements.txt --q
) else (
    echo ^> No requirements.txt found, skipping dependency install.
)

REM loading gui
echo ^> Starting web GUI
python -m tkinterGUI.deepdelverGUI

echo ^> DeepDelver closed. Press any key to close this window.
pause >nul
