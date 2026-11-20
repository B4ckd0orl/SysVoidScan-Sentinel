@echo off
title SysVoidScan
cd /d "%~dp0"

rem Consola en UTF-8 para que los acentos y simbolos se vean bien
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
set PYTHONUTF8=1
set PYTHONPATH=%CD%

if not exist ".venv\Scripts\python.exe" (
    echo.
    echo  [ERROR] No se encontro el entorno virtual .venv
    echo  Crea uno con:  "C:\Program Files\Python312\python.exe" -m venv .venv
    echo.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" main.py %*

echo.
pause
