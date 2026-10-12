@echo off
python "%~dp0tools\gradle_bootstrap.py" %*
exit /b %errorlevel%
