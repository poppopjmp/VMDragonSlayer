@echo off
REM VMDragonTaint Pin Tool Build Script for Windows
REM Alternative to Makefile for Windows environments

setlocal enabledelayedexpansion

echo VMDragonTaint Pin Tool Build Script
echo ===================================

REM Check if PIN_ROOT is set
if "%PIN_ROOT%"=="" (
    echo ERROR: PIN_ROOT environment variable not set
    echo Please set PIN_ROOT to your Intel Pin installation directory
    echo Example: set PIN_ROOT=C:\intel\pin
    exit /b 1
)

REM Check if Pin installation exists
if not exist "%PIN_ROOT%\pin.exe" (
    echo ERROR: Pin installation not found at %PIN_ROOT%
    echo Please verify PIN_ROOT points to a valid Pin installation
    exit /b 1
)

echo Pin installation found: %PIN_ROOT%

REM Create output directory
if not exist "obj-intel64" mkdir obj-intel64

REM Set build variables
set CONFIG_ROOT=%PIN_ROOT%\source\tools\Config
set TOOLS_ROOT=%PIN_ROOT%\source\tools

REM Include Pin configuration (simplified for Windows)
set TOOL_CXXFLAGS=-std=c++11 -O2 -g -Wall -D_WIN32 -DWIN32_LEAN_AND_MEAN
set TOOL_LDFLAGS=
set COMP_OBJ=-shared -o 

REM Build command
echo Building VMDragonTaint.dll...
g++ %TOOL_CXXFLAGS% %COMP_OBJ%obj-intel64\VMDragonTaint.dll VMDragonTaint.cpp %TOOL_LDFLAGS% -I"%PIN_ROOT%\source\include\pin" -I"%PIN_ROOT%\source\include\pin\gen" -L"%PIN_ROOT%\intel64\lib" -L"%PIN_ROOT%\intel64\lib-ext" -lpin -lxed -lpindwarf

if %ERRORLEVEL% neq 0 (
    echo ERROR: Build failed
    exit /b 1
)

echo Build successful!
echo Output: obj-intel64\VMDragonTaint.dll
echo.
echo Usage:
echo %PIN_ROOT%\pin.exe -t obj-intel64\VMDragonTaint.dll [options] -- target_binary.exe
echo.
echo Example:
echo %PIN_ROOT%\pin.exe -t obj-intel64\VMDragonTaint.dll -o taint.log -- notepad.exe

endlocal
