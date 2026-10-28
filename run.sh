#!/usr/bin/env bash
# =============================================================================
# Explainable SDN-Based Network Defence Appliance — Linux/macOS Launcher
# =============================================================================
# Usage:
#   ./run.sh              Start both API and dashboard (default)
#   ./run.sh start        Same as above
#   ./run.sh stop         Stop all running services
#   ./run.sh status       Show service status
#   ./run.sh logs         Tail live logs
#   ./run.sh build        Build frontend only
# =============================================================================
set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_PORT="${SDN_DEMO_PORT:-18000}"
DASH_PORT="${SDN_DASH_PORT:-5173}"
API_HOST="${SDN_DEMO_HOST:-127.0.0.1}"
VENV_DIR="$REPO_ROOT/.venv"
FRONTEND_DIR="$REPO_ROOT/apps/frontend"
PID_DIR="$REPO_ROOT/var/run"
API_PID_FILE="$PID_DIR/api.pid"
DASH_PID_FILE="$PID_DIR/dashboard.pid"
LOG_DIR="$REPO_ROOT/var/log"
API_LOG="$LOG_DIR/api.log"
DASH_LOG="$LOG_DIR/dashboard.log"

# ── Colors ────────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${BLUE}▶${RESET}  $*"; }
success() { echo -e "${GREEN}✓${RESET}  $*"; }
warn()    { echo -e "${YELLOW}⚠${RESET}  $*"; }
error()   { echo -e "${RED}✗${RESET}  $*" >&2; }
header()  { echo -e "\n${BOLD}$*${RESET}"; }

# ── Helpers ───────────────────────────────────────────────────────────────────
pid_running() { [[ -f "$1" ]] && kill -0 "$(cat "$1")" 2>/dev/null; }

stop_service() {
    local name="$1" pid_file="$2"
    if pid_running "$pid_file"; then
        kill "$(cat "$pid_file")" 2>/dev/null && rm -f "$pid_file"
        success "Stopped $name"
    else
        rm -f "$pid_file"
        warn "$name was not running"
    fi
}

wait_for_port() {
    local port="$1" timeout="${2:-20}" i=0
    while ! (echo > /dev/tcp/127.0.0.1/"$port") 2>/dev/null; do
        sleep 1; ((i++))
        [[ $i -ge $timeout ]] && return 1
    done
    return 0
}

# ── Commands ──────────────────────────────────────────────────────────────────
cmd_check() {
    header "Checking prerequisites…"
    local ok=true

    # Python
    if command -v python3 &>/dev/null; then
        success "Python3: $(python3 --version)"
    else
        error "python3 not found — install Python 3.11+"
        ok=false
    fi

    # Virtual environment
    if [[ -d "$VENV_DIR" ]]; then
        success "Virtual environment: $VENV_DIR"
    else
        warn "Virtual environment not found — will create it"
    fi

    # Node.js (optional if dist/ already built)
    if command -v node &>/dev/null; then
        success "Node.js: $(node --version)"
    else
        if [[ -d "$FRONTEND_DIR/dist" ]]; then
            warn "Node.js not found — using pre-built frontend dist/"
        else
            error "Node.js not found and no pre-built dist/ — install Node.js 18+"
            ok=false
        fi
    fi

    # var/runtime permissions
    local runtime_dir="$REPO_ROOT/var/runtime"
    if [[ -d "$runtime_dir" ]] && [[ ! -w "$runtime_dir" ]]; then
        warn "var/runtime/ is not writable — fixing with sudo…"
        sudo chown -R "$(whoami)" "$runtime_dir" || true
    fi

    $ok || { error "Prerequisites not met. See README.md for setup instructions."; exit 1; }
}

cmd_setup() {
    header "Setting up environment…"

    # Create venv if needed
    if [[ ! -d "$VENV_DIR" ]]; then
        info "Creating Python virtual environment…"
        python3 -m venv "$VENV_DIR"
    fi

    # Install Python dependencies
    info "Installing Python dependencies…"
    "$VENV_DIR/bin/pip" install -q --upgrade pip
    "$VENV_DIR/bin/pip" install -q -e "$REPO_ROOT[demo]" 2>/dev/null || \
        "$VENV_DIR/bin/pip" install -q -e "$REPO_ROOT"
    success "Python dependencies installed"

    # Ensure var directories exist
    mkdir -p "$PID_DIR" "$LOG_DIR" "$REPO_ROOT/var/runtime" "$REPO_ROOT/var/models"
}

cmd_build() {
    header "Building frontend…"
    if ! command -v node &>/dev/null; then
        warn "Node.js not found — skipping build (pre-built dist/ will be used)"
        return 0
    fi
    if ! command -v npm &>/dev/null; then
        warn "npm not found — skipping build"
        return 0
    fi
    cd "$FRONTEND_DIR"
    info "Installing npm dependencies…"
    npm ci --silent
    info "Building production bundle…"
    npm run build
    success "Frontend built → apps/frontend/dist/"
    cd "$REPO_ROOT"
}

cmd_start() {
    cmd_check
    cmd_setup

    header "Starting Sentinel services…"
    mkdir -p "$PID_DIR" "$LOG_DIR"

    # ── API ───────────────────────────────────────────────────────────────
    if pid_running "$API_PID_FILE"; then
        warn "API already running (PID $(cat "$API_PID_FILE"))"
    else
        info "Starting API server on http://$API_HOST:$API_PORT …"
        SDN_CONTROLLER_SIM=1 \
        SDN_DEMO_HOST="$API_HOST" \
        SDN_DEMO_PORT="$API_PORT" \
        SDN_DEMO_CORS_ORIGIN="http://127.0.0.1:$DASH_PORT" \
            "$VENV_DIR/bin/python" -m apps.api.demo_app \
            >> "$API_LOG" 2>&1 &
        echo $! > "$API_PID_FILE"
        info "Waiting for API to be ready…"
        if wait_for_port "$API_PORT" 20; then
            success "API ready → http://$API_HOST:$API_PORT/api/v1/status"
        else
            error "API did not start in time. Check logs: $API_LOG"
            exit 1
        fi
    fi

    # Fix var/runtime permissions if written by another user (e.g. old Ryu run)
    local runtime_dir="$REPO_ROOT/var/runtime"
    if [[ -d "$runtime_dir" ]] && [[ ! -w "$runtime_dir" ]]; then
        warn "Fixing var/runtime ownership (needs sudo)…"
        sudo chown -R "$(whoami)" "$runtime_dir" 2>/dev/null || true
    fi

    # ── Dashboard ─────────────────────────────────────────────────────────
    if pid_running "$DASH_PID_FILE"; then
        warn "Dashboard already running (PID $(cat "$DASH_PID_FILE"))"
    else
        if [[ -d "$FRONTEND_DIR/dist" ]]; then
            info "Starting dashboard (pre-built) on http://127.0.0.1:$DASH_PORT …"
            python3 -m http.server "$DASH_PORT" \
                --bind 127.0.0.1 \
                --directory "$FRONTEND_DIR/dist" \
                >> "$DASH_LOG" 2>&1 &
            echo $! > "$DASH_PID_FILE"
            info "Waiting for dashboard to be ready…"
            if wait_for_port "$DASH_PORT" 15; then
                success "Dashboard ready → http://127.0.0.1:$DASH_PORT"
            else
                error "Dashboard did not start in time. Check logs: $DASH_LOG"
                exit 1
            fi
        else
            warn "No pre-built dist/ found. Run './run.sh build' first, or install Node.js."
        fi
    fi

    echo ""
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  Sentinel is LIVE                                ${RESET}"
    echo -e "${BOLD}${GREEN}═══════════════════════════════════════════════${RESET}"
    echo -e "  Dashboard  →  ${BLUE}http://127.0.0.1:$DASH_PORT${RESET}"
    echo -e "  API        →  ${BLUE}http://$API_HOST:$API_PORT/api/v1/status${RESET}"
    echo -e "  Logs       →  $LOG_DIR/"
    echo -e "  Stop       →  ${YELLOW}./run.sh stop${RESET}"
    echo ""
}

cmd_stop() {
    header "Stopping Sentinel services…"
    stop_service "API"       "$API_PID_FILE"
    stop_service "Dashboard" "$DASH_PID_FILE"
}

cmd_status() {
    header "Sentinel service status"
    if pid_running "$API_PID_FILE"; then
        success "API       RUNNING (PID $(cat "$API_PID_FILE")) → http://$API_HOST:$API_PORT"
    else
        error "API       STOPPED"
    fi
    if pid_running "$DASH_PID_FILE"; then
        success "Dashboard RUNNING (PID $(cat "$DASH_PID_FILE")) → http://127.0.0.1:$DASH_PORT"
    else
        error "Dashboard STOPPED"
    fi
}

cmd_logs() {
    header "Tailing logs (Ctrl+C to exit)…"
    tail -f "$API_LOG" "$DASH_LOG" 2>/dev/null || {
        warn "No logs yet — start the services first with: ./run.sh start"
    }
}

# ── Entry point ───────────────────────────────────────────────────────────────
cd "$REPO_ROOT"
case "${1:-start}" in
    start)   cmd_start  ;;
    stop)    cmd_stop   ;;
    status)  cmd_status ;;
    logs)    cmd_logs   ;;
    build)   cmd_build  ;;
    setup)   cmd_setup  ;;
    check)   cmd_check  ;;
    restart) cmd_stop; sleep 1; cmd_start ;;
    *)
        echo "Usage: ./run.sh {start|stop|status|logs|build|restart}"
        exit 1
        ;;
esac

