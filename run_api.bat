@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\activate.bat" ( echo Run setup.bat first. & pause & exit /b 1 )
call ".venv\Scripts\activate.bat"
echo Starting the API on http://127.0.0.1:8000   (interactive docs: http://127.0.0.1:8000/docs)
echo Close this window or press Ctrl+C to stop it.
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
pause
