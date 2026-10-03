@echo off
chcp 65001 >nul
cd /d "%~dp0"
title 关闭开机自动登录

call :find_python
if not defined PY goto :nopy

"%PY%" "%~dp0campus_login.py" --autostart off
echo.
echo ---- 当前开机自启动状态 ----
"%PY%" "%~dp0campus_login.py" --autostart status
echo.
pause
exit /b 0

:find_python
set "PY="
for /f "delims=" %%i in ('where python.exe 2^>nul') do (
    if not defined PY (
        "%%i" -c "import tkinter" >nul 2>nul && set "PY=%%i"
    )
)
if not defined PY if exist "D:\Python\Python313\python.exe" set "PY=D:\Python\Python313\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
exit /b 0

:nopy
echo.
echo   [错误] 没有找到可用的 Python。
echo   请直接打开 CampusNetLogin.exe，用界面里的「开机自动登录」开关操作。
echo.
pause
exit /b 1
