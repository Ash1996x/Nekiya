@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "PATH=C:\msys64\mingw64\bin;%PATH%"
set "SRC=%~dp0src"
set "VEND=%~dp0vendor"
set "OUT=%~dp0out"
set "CFLAGS=-g0 -O2 -Wall -Wextra -Werror -std=c11 -D_WIN32_WINNT=0x0601 -DWINVER=0x0601 -D_CRT_SECURE_NO_WARNINGS"
set "FAIL=0"

if not exist "%OUT%" mkdir "%OUT%"
if errorlevel 1 (
    echo ERROR: cannot create %OUT%
    exit /b 1
)

echo [build] vendor lsapi
gcc %CFLAGS% -DLSAPI_IMPL -I"%VEND%" -c "%VEND%\lsapi\init.c" -o "%OUT%\lsapi_init.o"
if errorlevel 1 ( echo BUILD FAIL: lsapi init.c & set /a FAIL+=1 )
gcc %CFLAGS% -DLSAPI_IMPL -I"%VEND%" -c "%VEND%\lsapi\virtual.c" -o "%OUT%\lsapi_virtual.o"
if errorlevel 1 ( echo BUILD FAIL: lsapi virtual.c & set /a FAIL+=1 )
gcc %CFLAGS% -DLSAPI_IMPL -Wno-error=int-conversion -I"%VEND%" -c "%VEND%\lsapi\process.c" -o "%OUT%\lsapi_process.o"
if errorlevel 1 ( echo BUILD FAIL: lsapi process.c & set /a FAIL+=1 )

set "COMMON="%SRC%\ft_main.c" "%SRC%\ft_util.c" "%SRC%\ft_km.c" "%SRC%\ft_pe.c" "%SRC%\ft_proc.c" "%SRC%\ft_hide.c" "%SRC%\ft_elev.c" "%SRC%\ft_blind.c" "%SRC%\ft_edrcb.c" "%SRC%\ft_ppl.c""
set "OBJS=%OUT%\lsapi_init.o %OUT%\lsapi_virtual.o %OUT%\lsapi_process.o"

if "!FAIL!"=="0" (
    echo [build] nekiya.exe (production - no diagnostic switches)
    gcc %CFLAGS% -s -I"%SRC%" -I"%VEND%" -o "%OUT%\nekiya.exe" ^
        "%SRC%\ft_main.c" "%SRC%\ft_util.c" "%SRC%\ft_km.c" "%SRC%\ft_pe.c" "%SRC%\ft_proc.c" "%SRC%\ft_hide.c" "%SRC%\ft_elev.c" "%SRC%\ft_blind.c" "%SRC%\ft_edrcb.c" "%SRC%\ft_ppl.c" ^
        "%OUT%\lsapi_init.o" "%OUT%\lsapi_virtual.o" "%OUT%\lsapi_process.o" ^
        -ladvapi32 -lshell32
    if errorlevel 1 (
        echo BUILD FAIL: nekiya.exe
        set /a FAIL+=1
    )
)

if "!FAIL!"=="0" (
    echo [build] nekiya-lab.exe (lab build - adds --selftest/--doctor/--exports)
    gcc %CFLAGS% -DFT_DIAGNOSTICS -s -I"%SRC%" -I"%VEND%" -o "%OUT%\nekiya-lab.exe" ^
        "%SRC%\ft_main.c" "%SRC%\ft_util.c" "%SRC%\ft_km.c" "%SRC%\ft_pe.c" "%SRC%\ft_proc.c" "%SRC%\ft_hide.c" "%SRC%\ft_elev.c" "%SRC%\ft_blind.c" "%SRC%\ft_edrcb.c" "%SRC%\ft_ppl.c" ^
        "%SRC%\ft_self.c" "%OUT%\lsapi_init.o" "%OUT%\lsapi_virtual.o" "%OUT%\lsapi_process.o" ^
        -ladvapi32 -lshell32
    if errorlevel 1 (
        echo BUILD FAIL: nekiya-lab.exe
        set /a FAIL+=1
    )
)

if not "!FAIL!"=="0" (
    echo BUILD: !FAIL! step^(s^) failed
    exit /b !FAIL!
)

echo [build] selftest (lab build)
"%OUT%\nekiya-lab.exe" --selftest
if errorlevel 1 (
    echo BUILD FAIL: selftest reported failures
    set /a FAIL+=1
)

echo [build] FAIL=!FAIL!
exit /b !FAIL!
