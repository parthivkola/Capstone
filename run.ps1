# =============================================================================
# Explainable SDN-Based Network Defence Appliance — Windows Launcher
# =============================================================================
# Usage (run in PowerShell as normal user):
#   .\run.ps1              Start both API and dashboard
#   .\run.ps1 start        Same as above
#   .\run.ps1 stop         Stop all running services
#   .\run.ps1 status       Show service status
#   .\run.ps1 build        Build frontend only
#   .\run.ps1 logs         Open log files
# =============================================================================
param(
    [Parameter(Position=0)]
    [ValidateSet('start','stop','status','logs','build','setup','check','restart','')]
    [string]$Command = 'start'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ── Configuration ─────────────────────────────────────────────────────────────
$RepoRoot   = $PSScriptRoot
$ApiPort    = if ($env:SDN_DEMO_PORT)  { $env:SDN_DEMO_PORT }  else { '18000' }
$DashPort   = if ($env:SDN_DASH_PORT)  { $env:SDN_DASH_PORT }  else { '5173'  }
$ApiHost    = if ($env:SDN_DEMO_HOST)  { $env:SDN_DEMO_HOST }  else { '127.0.0.1' }
$VenvDir    = Join-Path $RepoRoot '.venv'
$FrontendDir= Join-Path $RepoRoot 'apps\frontend'
$PidDir     = Join-Path $RepoRoot 'var\run'
$LogDir     = Join-Path $RepoRoot 'var\log'
$ApiPid     = Join-Path $PidDir 'api.pid'
$DashPid    = Join-Path $PidDir 'dashboard.pid'
$ApiLog     = Join-Path $LogDir 'api.log'
$DashLog    = Join-Path $LogDir 'dashboard.log'

# ── Helpers ───────────────────────────────────────────────────────────────────
function Write-Info    { param($m) Write-Host "  ▶  $m" -ForegroundColor Cyan    }
function Write-Ok      { param($m) Write-Host "  ✓  $m" -ForegroundColor Green   }
function Write-Warn    { param($m) Write-Host "  ⚠  $m" -ForegroundColor Yellow  }
function Write-Err     { param($m) Write-Host "  ✗  $m" -ForegroundColor Red     }
function Write-Header  { param($m) Write-Host "`n$m" -ForegroundColor White      }

function Test-PidRunning {
    param([string]$PidFile)
    if (-not (Test-Path $PidFile)) { return $false }
    $pid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if (-not $pid) { return $false }
    return [bool](Get-Process -Id $pid -ErrorAction SilentlyContinue)
}

function Wait-ForPort {
    param([string]$Port, [int]$TimeoutSec = 20)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        try {
            $conn = New-Object System.Net.Sockets.TcpClient
            $conn.Connect('127.0.0.1', [int]$Port)
            $conn.Close()
            return $true
        } catch { Start-Sleep -Milliseconds 500 }
    }
    return $false
}

function Find-Python {
    foreach ($cmd in @('python', 'python3', 'py')) {
        $p = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($p) {
            $ver = & $p.Source --version 2>&1
            if ($ver -match '3\.1[0-9]') { return $p.Source }
        }
    }
    return $null
}

function Get-VenvPython {
    $py = Join-Path $VenvDir 'Scripts\python.exe'
    if (Test-Path $py) { return $py }
    return $null
}

function Stop-Service {
    param([string]$Name, [string]$PidFile)
    if (Test-PidRunning $PidFile) {
        $pid = [int](Get-Content $PidFile)
        Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
        Remove-Item $PidFile -ErrorAction SilentlyContinue
        Write-Ok "Stopped $Name"
    } else {
        Remove-Item $PidFile -ErrorAction SilentlyContinue
        Write-Warn "$Name was not running"
    }
}

# ── Commands ──────────────────────────────────────────────────────────────────
function Invoke-Check {
    Write-Header 'Checking prerequisites…'
    $ok = $true

    $python = Find-Python
    if ($python) {
        Write-Ok "Python: $(& $python --version 2>&1)"
    } else {
        Write-Err 'Python 3.11+ not found — download from https://python.org'
        $ok = $false
    }

    if (Test-Path $VenvDir) {
        Write-Ok "Virtual environment: $VenvDir"
    } else {
        Write-Warn 'Virtual environment not found — will create it'
    }

    $node = Get-Command node -ErrorAction SilentlyContinue
    if ($node) {
        Write-Ok "Node.js: $(node --version)"
    } else {
        if (Test-Path (Join-Path $FrontendDir 'dist')) {
            Write-Warn 'Node.js not found — using pre-built frontend dist\'
        } else {
            Write-Err 'Node.js not found and no pre-built dist\ — install from https://nodejs.org'
            $ok = $false
        }
    }

    if (-not $ok) {
        Write-Err 'Prerequisites not met. See README.md for setup instructions.'
        exit 1
    }
}

function Invoke-Setup {
    Write-Header 'Setting up environment…'
    $python = Find-Python
    if (-not $python) { Write-Err 'Python not found'; exit 1 }

    if (-not (Test-Path $VenvDir)) {
        Write-Info 'Creating Python virtual environment…'
        & $python -m venv $VenvDir
    }

    $venvPy = Join-Path $VenvDir 'Scripts\python.exe'
    Write-Info 'Installing Python dependencies…'
    & $venvPy -m pip install -q --upgrade pip
    & $venvPy -m pip install -q -e "$RepoRoot[demo]" 2>$null
    if ($LASTEXITCODE -ne 0) {
        & $venvPy -m pip install -q -e $RepoRoot
    }
    Write-Ok 'Python dependencies installed'

    foreach ($d in @($PidDir, $LogDir, "$RepoRoot\var\runtime", "$RepoRoot\var\models")) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

function Invoke-Build {
    Write-Header 'Building frontend…'
    if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
        Write-Warn 'Node.js not found — skipping build (pre-built dist\ will be used)'
        return
    }
    Push-Location $FrontendDir
    Write-Info 'Installing npm dependencies…'
    npm ci --silent
    Write-Info 'Building production bundle…'
    npm run build
    Write-Ok 'Frontend built → apps\frontend\dist\'
    Pop-Location
}

function Invoke-Start {
    Invoke-Check
    Invoke-Setup

    Write-Header 'Starting Sentinel services…'
    New-Item -ItemType Directory -Path $PidDir,$LogDir -Force | Out-Null

    $venvPy = Get-VenvPython
    if (-not $venvPy) { Write-Err 'Virtual environment not set up'; exit 1 }

    # ── API ───────────────────────────────────────────────────────────────
    if (Test-PidRunning $ApiPid) {
        Write-Warn "API already running (PID $(Get-Content $ApiPid))"
    } else {
        Write-Info "Starting API server on http://${ApiHost}:${ApiPort} …"
        $env:SDN_CONTROLLER_SIM = '1'
        $env:SDN_DEMO_HOST      = $ApiHost
        $env:SDN_DEMO_PORT      = $ApiPort
        $env:SDN_DEMO_CORS_ORIGIN = "http://127.0.0.1:$DashPort"
        $proc = Start-Process -FilePath $venvPy `
            -ArgumentList '-m', 'apps.api.demo_app' `
            -WorkingDirectory $RepoRoot `
            -RedirectStandardOutput $ApiLog `
            -RedirectStandardError  $ApiLog `
            -PassThru -WindowStyle Hidden
        $proc.Id | Set-Content $ApiPid
        Write-Info 'Waiting for API to be ready…'
        if (Wait-ForPort $ApiPort 20) {
            Write-Ok "API ready → http://${ApiHost}:${ApiPort}/api/v1/status"
        } else {
            Write-Err "API did not start. Check logs: $ApiLog"
            exit 1
        }
    }

    # ── Dashboard ─────────────────────────────────────────────────────────
    if (Test-PidRunning $DashPid) {
        Write-Warn "Dashboard already running (PID $(Get-Content $DashPid))"
    } else {
        $distDir = Join-Path $FrontendDir 'dist'
        if (Test-Path $distDir) {
            Write-Info "Starting dashboard (pre-built) on http://127.0.0.1:$DashPort …"
            $python = Find-Python
            $proc = Start-Process -FilePath $python `
                -ArgumentList '-m', 'http.server', $DashPort, '--bind', '127.0.0.1', '--directory', $distDir `
                -WorkingDirectory $RepoRoot `
                -RedirectStandardOutput $DashLog `
                -RedirectStandardError  $DashLog `
                -PassThru -WindowStyle Hidden
            $proc.Id | Set-Content $DashPid
            Write-Info 'Waiting for dashboard to be ready…'
            if (Wait-ForPort $DashPort 15) {
                Write-Ok "Dashboard ready → http://127.0.0.1:$DashPort"
            } else {
                Write-Err "Dashboard did not start. Check logs: $DashLog"
                exit 1
            }
        } else {
            Write-Warn 'No pre-built dist\ found. Run: .\run.ps1 build'
        }
    }

    Write-Host ''
    Write-Host '  ═══════════════════════════════════════════════' -ForegroundColor Green
    Write-Host '    Sentinel is LIVE                              ' -ForegroundColor White
    Write-Host '  ═══════════════════════════════════════════════' -ForegroundColor Green
    Write-Host "    Dashboard  →  http://127.0.0.1:$DashPort" -ForegroundColor Cyan
    Write-Host "    API        →  http://${ApiHost}:${ApiPort}/api/v1/status" -ForegroundColor Cyan
    Write-Host "    Logs       →  $LogDir\" -ForegroundColor Gray
    Write-Host "    Stop       →  .\run.ps1 stop" -ForegroundColor Yellow
    Write-Host ''
}

function Invoke-Stop {
    Write-Header 'Stopping Sentinel services…'
    Stop-Service 'API'       $ApiPid
    Stop-Service 'Dashboard' $DashPid
}

function Invoke-Status {
    Write-Header 'Sentinel service status'
    if (Test-PidRunning $ApiPid) {
        Write-Ok "API       RUNNING (PID $(Get-Content $ApiPid)) → http://${ApiHost}:${ApiPort}"
    } else {
        Write-Err 'API       STOPPED'
    }
    if (Test-PidRunning $DashPid) {
        Write-Ok "Dashboard RUNNING (PID $(Get-Content $DashPid)) → http://127.0.0.1:$DashPort"
    } else {
        Write-Err 'Dashboard STOPPED'
    }
}

function Invoke-Logs {
    Write-Header 'Opening log files…'
    if (Test-Path $ApiLog)  { Start-Process notepad $ApiLog }
    if (Test-Path $DashLog) { Start-Process notepad $DashLog }
    Write-Info "API log:       $ApiLog"
    Write-Info "Dashboard log: $DashLog"
}

# ── Entry point ───────────────────────────────────────────────────────────────
switch ($Command) {
    'start'   { Invoke-Start   }
    'stop'    { Invoke-Stop    }
    'status'  { Invoke-Status  }
    'logs'    { Invoke-Logs    }
    'build'   { Invoke-Build   }
    'setup'   { Invoke-Setup   }
    'check'   { Invoke-Check   }
    'restart' { Invoke-Stop; Start-Sleep -Seconds 1; Invoke-Start }
    default   { Invoke-Start   }
}

