@echo off
REM VMDragonSlayer Ghidra Plugin Build Script
REM Builds the enterprise agentic AI plugin for Ghidra

echo Building VMDragonSlayer Enterprise Agentic AI Plugin...
echo.

REM Set build directories
set SRC_DIR=src\main\java
set BUILD_DIR=build
set DIST_DIR=dist
set LIB_DIR=lib

REM Clean previous build
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"

REM Create build directories
mkdir "%BUILD_DIR%"
mkdir "%DIST_DIR%"
mkdir "%LIB_DIR%"

echo [1/4] Setting up build environment...

REM Check for Ghidra installation
if not defined GHIDRA_INSTALL_DIR (
    echo ERROR: GHIDRA_INSTALL_DIR environment variable not set
    echo Please set GHIDRA_INSTALL_DIR to your Ghidra installation directory
    pause
    exit /b 1
)

if not exist "%GHIDRA_INSTALL_DIR%" (
    echo ERROR: Ghidra installation directory not found: %GHIDRA_INSTALL_DIR%
    pause
    exit /b 1
)

echo Ghidra installation: %GHIDRA_INSTALL_DIR%
echo.

echo [2/4] Downloading dependencies...

REM Download Jackson JSON library for API communication
if not exist "%LIB_DIR%\jackson-core.jar" (
    echo Downloading Jackson Core...
    powershell -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-core/2.15.2/jackson-core-2.15.2.jar' -OutFile '%LIB_DIR%\jackson-core.jar'"
)

if not exist "%LIB_DIR%\jackson-databind.jar" (
    echo Downloading Jackson Databind...
    powershell -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-databind/2.15.2/jackson-databind-2.15.2.jar' -OutFile '%LIB_DIR%\jackson-databind.jar'"
)

if not exist "%LIB_DIR%\jackson-annotations.jar" (
    echo Downloading Jackson Annotations...
    powershell -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/com/fasterxml/jackson/core/jackson-annotations/2.15.2/jackson-annotations-2.15.2.jar' -OutFile '%LIB_DIR%\jackson-annotations.jar'"
)

echo.

echo [3/4] Compiling Java sources...

REM Set up classpath
set GHIDRA_JARS=%GHIDRA_INSTALL_DIR%\support\ghidra.jar
set JACKSON_JARS=%LIB_DIR%\jackson-core.jar;%LIB_DIR%\jackson-databind.jar;%LIB_DIR%\jackson-annotations.jar
set CLASSPATH=%GHIDRA_JARS%;%JACKSON_JARS%

REM Compile all Java source files
javac -cp "%CLASSPATH%" -d "%BUILD_DIR%" "%SRC_DIR%\vmdragonslayer\*.java"
if errorlevel 1 (
    echo ERROR: Failed to compile main plugin files
    pause
    exit /b 1
)

javac -cp "%CLASSPATH%;%BUILD_DIR%" -d "%BUILD_DIR%" "%SRC_DIR%\vmdragonslayer\api\*.java"
if errorlevel 1 (
    echo ERROR: Failed to compile API files
    pause
    exit /b 1
)

javac -cp "%CLASSPATH%;%BUILD_DIR%" -d "%BUILD_DIR%" "%SRC_DIR%\vmdragonslayer\ui\*.java"
if errorlevel 1 (
    echo ERROR: Failed to compile UI files
    pause
    exit /b 1
)

javac -cp "%CLASSPATH%;%BUILD_DIR%" -d "%BUILD_DIR%" "%SRC_DIR%\vmdragonslayer\integration\*.java"
if errorlevel 1 (
    echo ERROR: Failed to compile integration files
    pause
    exit /b 1
)

echo Compilation successful!
echo.

echo [4/4] Creating plugin JAR...

REM Copy manifest
mkdir "%BUILD_DIR%\META-INF"
copy "META-INF\MANIFEST.MF" "%BUILD_DIR%\META-INF\"

REM Copy plugin properties
copy "plugin.properties" "%BUILD_DIR%\"

REM Create JAR file
cd "%BUILD_DIR%"
jar cfm "..\%DIST_DIR%\VMDragonSlayer.jar" "META-INF\MANIFEST.MF" vmdragonslayer\ plugin.properties
cd ..

REM Copy dependencies to distribution
mkdir "%DIST_DIR%\lib"
copy "%LIB_DIR%\*.jar" "%DIST_DIR%\lib\"

echo.
echo ===================================
echo VMDragonSlayer Plugin Build Complete!
echo ===================================
echo.
echo Plugin JAR: %DIST_DIR%\VMDragonSlayer.jar
echo Dependencies: %DIST_DIR%\lib\
echo.
echo Installation Instructions:
echo 1. Copy VMDragonSlayer.jar to your Ghidra Extensions directory
echo 2. Copy lib\ folder contents to Ghidra's lib directory
echo 3. Restart Ghidra and enable the VMDragonSlayer plugin
echo 4. Ensure the Python agentic API is running on http://127.0.0.1:8000
echo.
echo Enterprise Features Available:
echo - 5 Active Analysis Engines (Hybrid, Parallel, DTT, Symbolic, ML)
echo - AI-Driven Decision Making with Confidence Scoring
echo - Real-time WebSocket Streaming and Monitoring
echo - Performance Metrics and Resource Optimization
echo - Enterprise Engine Status Dashboard
echo.
pause
