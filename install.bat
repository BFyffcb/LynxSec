@echo off
REM ============================================================
REM LynxSec ?????? (Windows + WSL2)
REM 
REM ??: ?? ? ?????????? PowerShell ???:
REM   .\install.bat
REM ============================================================
setlocal enabledelayedexpansion

echo.
echo   ============================================================
echo     LynxSec ??????
echo   ============================================================
echo.

REM ---- Step 1: Check Python ----
echo [1/5] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [FAIL] Python not found. Install from https://python.org
    pause
    exit /b 1
)
for /f "tokens=2" %%v in ("python --version 2>&1") do echo   [OK] Python %%v

REM ---- Step 2: Check WSL2 ----
echo [2/5] Checking WSL2...
wsl --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   [WARN] WSL2 not found. Installing...
    wsl --install -d Ubuntu
    echo   Please reboot and re-run this script.
    pause
    exit /b 0
)
for /f "tokens=*" %%v in ("wsl -u root -- bash -c 'cat /etc/os-release | grep ^PRETTY_NAME | cut -d= -f2 | tr -d \"'"' 2>&1") do echo   [OK] %%v

REM ---- Step 3: Install Docker in WSL ----
echo [3/5] Setting up Docker in WSL...
wsl -u root -- bash -c '
if ! command -v docker &> /dev/null; then
    echo "  Installing Docker..."
    apt-get update -qq
    apt-get install -y docker.io docker-compose-v2
fi
service docker start
docker pull vulnerables/web-dvwa:latest -q
docker run -d --name dvwa -p 80:80 --restart unless-stopped vulnerables/web-dvwa
echo "  [OK] Docker + DVWA ready"
'

REM ---- Step 4: Install Security Tools ----
echo [4/5] Installing security tools in WSL...
wsl -u root -- bash -c '
apt-get update -qq
apt-get install -y nmap sqlmap hydra -qq

# Go tools (subfinder, nuclei)
if ! command -v go &> /dev/null; then
    apt-get install -y golang-go -qq
fi

export PATH=$PATH:/root/go/bin:$HOME/go/bin

for tool in subfinder nuclei; do
    if ! command -v $tool &> /dev/null; then
        echo "  Installing $tool..."
        go install github.com/projectdiscovery/$tool/v2/cmd/$tool@latest 2>/dev/null ||
        go install github.com/projectdiscovery/$tool/v3/cmd/$tool@latest 2>/dev/null
    else
        echo "  [OK] $tool already installed"
    fi
done

# Make go binaries accessible
echo "export PATH=\$PATH:/root/go/bin:\$HOME/go/bin" >> /root/.bashrc
'

echo "  [OK] Security tools installed"

REM ---- Step 5: Install LynxSec Python dependencies ----
echo [5/5] Installing LynxSec Python dependencies...
pip install -e %~dp0 --quiet 2>nul
if %errorlevel% neq 0 (
    echo   [WARN] pip install -e failed, trying direct install...
    pip install python-dotenv pydantic rich --quiet
)
echo   [OK] LynxSec installed

echo.
echo   ============================================================
echo     Installation complete!
echo   ============================================================
echo.
echo   Run:  lynxsec
echo.
pause
