@echo off
setlocal
cd /d "%~dp0"
echo ============================================================
echo  Phishing Email Detector - one-time setup
echo ============================================================

rem ---- find a Python (3.12 preferred: best PyTorch support) ----
set "PY="
for %%V in (3.12 3.13 3.11 3.14) do (
  if not defined PY (
    py -%%V -c "import sys" >nul 2>&1 && set "PY=py -%%V"
  )
)
if not defined PY (
  python -c "import sys" >nul 2>&1 && set "PY=python"
)
if not defined PY (
  echo.
  echo  Python was not found on this PC.
  echo  Install Python 3.12 from https://www.python.org/downloads/
  echo  and TICK "Add python.exe to PATH" in the installer, then run this again.
  pause
  exit /b 1
)
echo Using Python: %PY%
%PY% --version

rem ---- virtual environment ----
if not exist ".venv\Scripts\python.exe" (
  echo.
  echo Creating virtual environment in .venv ...
  %PY% -m venv .venv
  if errorlevel 1 ( echo Could not create the virtual environment. & pause & exit /b 1 )
)
call ".venv\Scripts\activate.bat"

rem ---- packages (first time takes 5-15 minutes: PyTorch is large) ----
echo.
echo Installing packages - this can take a while the first time...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 ( echo. & echo Package install failed - see the error above. & pause & exit /b 1 )

rem ---- register the venv as a Jupyter kernel ----
python -m ipykernel install --user --name phishing-venv --display-name "Python (phishing project)"

rem ---- checks ----
echo.
echo Checking everything works...
python -c "import torch, sklearn, fastapi, uvicorn, pandas, matplotlib, tkinter; print('  Packages OK  (torch', torch.__version__, ')')"
if errorlevel 1 ( echo Package check failed. & pause & exit /b 1 )
python -c "import sys; sys.path.insert(0, '.'); from phishing_core.model import PhishingDetector; d = PhishingDetector('models'); r = d.analyse('Cheap replica watches', 'Buy luxury replica watches now!!! www.best-replicas.biz', explain=False); print('  Model OK     (test email ->', r['label'], round(r['probability'], 3), ')')"
if errorlevel 1 ( echo Model check failed - is the models folder there? & pause & exit /b 1 )

echo.
echo ============================================================
echo  Setup complete.
echo    run_demo.bat  - starts the API and opens the desktop app
echo    run_api.bat   - starts only the API (http://127.0.0.1:8000/docs)
echo  To retrain: open notebooks\02_model_training.ipynb in VS Code,
echo  pick the kernel "Python (phishing project)" or .venv, then Run All.
echo ============================================================
pause
