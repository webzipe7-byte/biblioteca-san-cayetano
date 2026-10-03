@echo off
chcp 65001 >nul
title Biblioteca Virtual - Colegio San Cayetano
cd /d "%~dp0"
start "" /min cmd /c "timeout /t 2 >nul & start http://localhost:3000"
node server.js
pause
