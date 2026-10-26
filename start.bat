@echo off
cd /d %~dp0
start "CyberGuard API" cmd /k "venv\Scripts\activate && uvicorn server:app --port 8001"
timeout /t 4 >nul
start "CyberGuard UI" cmd /k "venv\Scripts\activate && python -m http.server 3000"
timeout /t 2 >nul
start http://localhost:3000/index.html
start http://localhost:8001/docs
