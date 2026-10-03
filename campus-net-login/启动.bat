@echo off
chcp 65001 >nul
cd /d "%~dp0"
title 校园网自动登录助手

rem ---- 1) 优先使用打包好的免安装 exe ----
if exist "%~dp0CampusNetLogin.exe" (
    start "" "%~dp0CampusNetLogin.exe"
    exit /b
)

rem ---- 2) 查找带 tkinter 的 Python（用 pythonw.exe，不弹黑窗）----
set "PYW="
for /f "delims=" %%i in ('where pythonw.exe 2^>nul') do (
    if not defined PYW (
        "%%i" -c "import tkinter" >nul 2>nul && set "PYW=%%i"
    )
)
if not defined PYW if exist "D:\Python\Python313\pythonw.exe" set "PYW=D:\Python\Python313\pythonw.exe"
if not defined PYW if exist "%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python313\pythonw.exe"

if not defined PYW (
    echo.
    echo   [错误] 没有找到带图形组件 tkinter 的 Python。
    echo.
    echo   解决方式二选一：
    echo     1) 安装官方 Python 3.8+（安装包自带 tkinter），
    echo        安装时勾选 "Add Python to PATH"；
    echo     2) 直接使用同目录下的 CampusNetLogin.exe（免安装版本）。
    echo.
    echo   另外：没有 tkinter 也可以使用命令行模式，例如
    echo         python campus_login.py --connect
    echo.
    pause
    exit /b 1
)

start "" "%PYW%" "%~dp0campus_login.py"
exit /b
