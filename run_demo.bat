@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\activate.bat" ( echo Run setup.bat first. & pause & exit /b 1 )
echo Starting the API in a separate window...
start "Phishing API" cmd /k "%~dp0run_api.bat"
echo Waiting for the model to load...
timeout /t 8 /nobreak >nul
call ".venv\Scripts\activate.bat"
python app\desktop_app.py
