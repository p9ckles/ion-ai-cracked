@echo off
setlocal
REM ============================================================
REM  start_ion.bat  -  one-shot launcher
REM
REM  Starts the auth server (python) FIRST, waits until it is
REM  really listening on 127.0.0.1:3389, then opens ION_Pro.exe.
REM
REM  Double-click it - it will ask for elevation by itself.
REM  (Right-click ^> Run as administrator works too.)
REM
REM  Every step is recorded in start_ion.log next to this file.
REM ============================================================

set "HERE=%~dp0"
set "LOG=%HERE%start_ion.log"
cd /d "%HERE%"

REM ---------------------------------------------------------- elevation
net session >nul 2>&1
if not errorlevel 1 goto elevated

call :say "[!] Administrator rights are needed to patch the hosts file."
call :say "[*] Requesting elevation..."
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
if errorlevel 1 (
    call :say "[!] Elevation was cancelled."
    pause
    exit /b 1
)
exit /b 0

:elevated
call :say "[*] Running elevated."

REM ---------------------------------------------------------- python
call :say "[*] Checking Python..."
set "PY=python"

%PY% --version >nul 2>&1
if errorlevel 1 (
    call :say "[!] Python not found: https://www.python.org/downloads/"
    call :say "[!] Tick 'Add python.exe to PATH' during install, then rerun this."
    pause
    exit /b 1
)
call :say "[*] Using: %PY%"

%PY% -c "import cryptography" >nul 2>&1
if errorlevel 1 (
    call :say "[*] Installing cryptography..."
    %PY% -m pip install cryptography
    if errorlevel 1 (
        call :say "[!] pip install failed - check the internet and try again."
        pause
        exit /b 1
    )
)

REM ---------------------------------------------------------- locate python script
set "PY_SCRIPT="
if exist "%HERE%dist\ioncrack.py" (
    set "PY_SCRIPT=%HERE%dist\ioncrack.py"
    set "PY_DIR=%HERE%dist"
) else if exist "%HERE%ioncrack.py" (
    set "PY_SCRIPT=%HERE%ioncrack.py"
    set "PY_DIR=%HERE%"
) else (
    call :say "[!] Neither dist\ioncrack.py nor ioncrack.py was found."
    pause
    exit /b 1
)

REM ---------------------------------------------------------- step 1: python
call :portcheck
if not errorlevel 1 (
    call :say "[*] Auth server already listening on 127.0.0.1:3389 - reusing it."
    goto step2
)

call :say ""
call :say "[*] Step 1 of 2: starting the auth server (python) first..."
call :say "[*] Script path: %PY_SCRIPT%"
start "ION Auth Server" /d "%PY_DIR%" cmd /k "python "%PY_SCRIPT%""

call :say "[*] Waiting for 127.0.0.1:3389 ..."
set /a _tries=0
:waitport
call :portcheck
if not errorlevel 1 goto portready
set /a _tries+=1
if %_tries% geq 30 goto portfail
ping -n 2 127.0.0.1 >nul
goto waitport

:portfail
call :say "[!] The server did not come up on port 3389."
call :say "[!] Read the 'ION Auth Server' window - most common cause is"
call :say "[!] another program already holding port 3389 or a missing VC++ runtime."
echo.
pause
exit /b 1

:portready
call :say "[+] Server is up."

REM ---------------------------------------------------------- step 2: the exe
:step2
tasklist /fi "imagename eq ION_Pro.exe" 2>nul | findstr /i "ION_Pro.exe" >nul
if not errorlevel 1 (
    call :say "[*] ION_Pro.exe already running - not starting a second copy."
    goto done
)

call :say ""
call :say "[*] Step 2 of 2: opening ION_Pro.exe ..."
start "" /d "%HERE%" ION_Pro.exe
if errorlevel 1 (
    call :say "[!] Could not start ION_Pro.exe"
    pause
    exit /b 1
)
call :say "[+] ION_Pro.exe started."

:done
call :say ""
call :say "[+] Done - server first, then the app."
call :say "[+] Server log : %HERE%ion_server.log"
call :say "[+] Web UI     : http://127.0.0.1:17676"
echo.
ping -n 4 127.0.0.1 >nul
exit /b 0


REM ============================================================
REM  helpers - reached only via "call"
REM ============================================================

:portcheck
netstat -ano | findstr "LISTENING" | findstr "127.0.0.1:3389" >nul 2>&1
exit /b %errorlevel%

:say
echo(%~1
>>"%LOG%" echo [%time:~0,8%] %~1
goto :eof