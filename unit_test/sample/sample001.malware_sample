@echo off
REM so sus ngl :sob:
setlocal
title Vixen Free Perm Woofer
echo made by conspiracy.
echo.
echo.

CD /D "%~dp0"
REM Check if the UTIL folder exists
if not exist "UTIL\" (
    echo Please extract the folder, it MUST NOT be run without extracting.
    pause
    exit /b
)

endlocal


>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~s0""", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    cd /d "%~dp0"

cd /d "UTIL"

setlocal enabledelayedexpansion

:ask
set "response="
set /p "response=Would you like to randomize serials? If no, it makes them Default String/OEM filled. (y/n): "
set "response=!response:~0,1!"
color b
if /i "!response!"=="y" (
    echo randomizing.
    conspiracy /BM "To Be Filled By O.E.M."
    conspiracy /SM "To Be Filled By O.E.M."
    conspiracy /SS "V%RANDOM%%RANDOM%-JTZ-%RANDOM%%RANDOM%-XN%RANDOM%"
    conspiracy /BS "V%RANDOM%%RANDOM%-ATS-%RANDOM%%RANDOM%-XN%RANDOM%"
    conspiracy /BP "V%RANDOM%%RANDOM%-73Z-%RANDOM%%RANDOM%-XN%RANDOM%"
    conspiracy /SP "V%RANDOM%%RANDOM%-P5A-%RANDOM%%RANDOM%-XN%RANDOM%"
    conspiracy /PSN "V%RANDOM%%RANDOM%-N7F-%RANDOM%%RANDOM%-XN%RANDOM%"
    conspiracy /SU auto
    timeout /T 3 >nul
    echo.
    echo.
    echo.
    echo.
    echo.
    echo.
    echo done.
    echo please restart pc :3
    echo made by conspiracy
    echo free in discord.gg/vixen!
    echo press any key to exit!
    pause>nul
    exit /B
) else if /i "!response!"=="n" (
    echo setting serials to OEM Filled.
    conspiracy /BM "To Be Filled By O.E.M."
    conspiracy /SM "To Be Filled By O.E.M."
    conspiracy /SS "To Be Filled By O.E.M."
    conspiracy /SP "To Be Filled By O.E.M."
    conspiracy /BP "To Be Filled By O.E.M."
    conspiracy /BS "To Be Filled By O.E.M."
    conspiracy /PSN "Default String"
    conspiracy /SU auto
    timeout /T 3 >nul
    echo.
    echo.
    echo.
    echo.
    echo.
    echo.
    echo done.
    echo please restart pc :3
    echo made by conspiracy
    echo free in discord.gg/vixen!
    echo press any key to exit!
    pause>nul
    exit /B

) else (
    echo Invalid input. Please enter y/n or yes/no.
    goto ask
)

endlocal
pause>nul