@echo off
rem ServerLog Analyzer - double-click to start (opens in your browser)
cd /d "%~dp0"
where pyw >nul 2>nul
if %errorlevel%==0 (
  start "" pyw -3 "%~dp0launch_log_analyzer.py" %*
  exit /b
)
where pythonw >nul 2>nul
if %errorlevel%==0 (
  start "" pythonw "%~dp0launch_log_analyzer.py" %*
  exit /b
)
echo Python 3 is not installed. Please install it from https://www.python.org/downloads/
pause
