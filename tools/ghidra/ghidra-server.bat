@echo off
rem Serve the Ghidra project of one build of The Sims 4 on 127.0.0.1 without the GUI, for the MCP server ghidra-ts4
rem and ghcat.py.
rem Usage: tools\ghidra\ghidra-server.bat [build] [port]
rem   build: the build to serve, <module>_<version> (the project <workspace>\ghidra\<build>\ts4.gpr). The default is
rem          Simulation_x64 of the game version now (GameVersion.txt).
rem   port:  8083 by default; 8084 for a second build. Never 8080, 8081 or 8082: other projects use them.
rem Stop it with: curl -X POST http://127.0.0.1:8083/shutdown
rem While it runs, the Ghidra GUI cannot open the project.
rem The workspace is the folder that holds projects: TS4_WORKSPACE, else two folders above this repository.
rem TS4_GHIDRA_ROOT can give another folder for the Ghidra projects.
setlocal
if defined TS4_WORKSPACE (set "WS=%TS4_WORKSPACE%") else for %%w in ("%~dp0..\..\..\..") do set "WS=%%~fw"
if defined TS4_GHIDRA_ROOT (set "GHIDRA_ROOT=%TS4_GHIDRA_ROOT%") else set "GHIDRA_ROOT=%WS%\ghidra"
set "RUNS=%WS%\runs"
set BUILD=%~1
set PORT=%~2
if "%PORT%"=="" set PORT=8083
if "%PORT%"=="8080" goto badport
if "%PORT%"=="8081" goto badport
if "%PORT%"=="8082" goto badport
if "%BUILD%"=="" for /f "usebackq delims=" %%g in (`python "%~dp0ghidra_builds.py" current`) do set BUILD=%%g
if "%BUILD%"=="" (
  echo Cannot read the game version. Give the build as the first argument.
  exit /b 1
)
python "%~dp0ghidra_builds.py" check-project %BUILD%
if errorlevel 1 exit /b 1
for /f "usebackq delims=" %%p in (`python -c "import json,sys; print(json.load(open(sys.argv[1]))['program'])" "%GHIDRA_ROOT%\%BUILD%\build.json"`) do set PROGRAM=%%p
if "%PROGRAM%"=="" (
  echo %GHIDRA_ROOT%\%BUILD%\build.json does not name the program.
  exit /b 1
)
if not defined GHIDRA_INSTALL_DIR set GHIDRA_INSTALL_DIR=C:\tools\ghidra
if not defined GHIDRA_HEADLESS_MAXMEM set GHIDRA_HEADLESS_MAXMEM=12G
if not exist "%RUNS%" mkdir "%RUNS%"
echo Serve %PROGRAM% of build %BUILD% on 127.0.0.1:%PORT%
"%GHIDRA_INSTALL_DIR%\support\analyzeHeadless.bat" "%GHIDRA_ROOT%\%BUILD%" ts4 ^
  -process %PROGRAM% -noanalysis ^
  -scriptPath "%~dp0." ^
  -postScript Ts4McpServer.java %PORT% %BUILD% ^
  -log "%RUNS%\ghidra-server-%PORT%.log" ^
  -scriptlog "%RUNS%\ghidra-server-script-%PORT%.log"
exit /b %errorlevel%

:badport
echo Port %PORT% belongs to another project. Use 8083 or 8084.
exit /b 1
