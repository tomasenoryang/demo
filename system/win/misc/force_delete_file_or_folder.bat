@echo off
chcp 65001 >nul

rem === 检查是否传入参数 ===
if "%~1"=="" (
    echo 请传入要删除的文件或文件夹路径。
    echo 用法: %~nx0 路径
    exit /b 1
)

set "TARGET_PATH=%~1"

echo 正在处理路径: %TARGET_PATH%

echo === 正在接管所有权 ===
takeown /f "%TARGET_PATH%" /r /d y >nul 2>&1

echo === 正在授予管理员权限 ===
icacls "%TARGET_PATH%" /grant Administrators:F /t /c >nul 2>&1

echo === 正在删除文件或文件夹 ===
rd /s /q "%TARGET_PATH%" 2>nul
del /f /q "%TARGET_PATH%" 2>nul

echo === 删除完成 ===

endlocal
