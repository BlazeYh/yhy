@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"
title 校园网登录 - 真实环境自测

rem ---- 查找可用的 Python（这里只需 3.8+，不依赖 tkinter）----
set "PY="
for /f "delims=" %%i in ('where python.exe 2^>nul') do (
    if not defined PY (
        "%%i" -c "import sys;assert sys.version_info>=(3,8)" >nul 2>nul && set "PY=%%i"
    )
)
if not defined PY if exist "D:\Python\Python313\python.exe" set "PY=D:\Python\Python313\python.exe"
if not defined PY if exist "%LOCALAPPDATA%\Programs\Python\Python313\python.exe" set "PY=%LOCALAPPDATA%\Programs\Python\Python313\python.exe"

if not defined PY (
    echo.
    echo   [错误] 没找到可用的 Python 解释器。
    echo.
    echo   备选方案：直接用 exe 手动测试，例如
    echo       CampusNetLogin.exe --probe
    echo       CampusNetLogin.exe --connect
    echo.
    pause
    exit /b 1
)

echo 使用解释器: %PY%
echo.
echo 提示：整个过程约需 30~60 秒（含网络超时等待），请勿关闭本窗口。
echo.
"%PY%" "%~dp0tests\selftest_real.py" %*
echo.
if exist "%~dp0测试结果.txt" start "" "%~dp0测试结果.txt"
echo 以上报告已保存为 测试结果.txt，可直接发回分析。
pause
