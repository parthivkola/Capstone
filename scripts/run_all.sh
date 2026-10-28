#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
RUNTIME_DIR="${SENTINEL_RUNTIME_DIR:-${ROOT}/var/run-all}"
[[ "$RUNTIME_DIR" == /* ]] || RUNTIME_DIR="${ROOT}/${RUNTIME_DIR}"
PID_FILE="${RUNTIME_DIR}/launcher.pid"
LOG_FILE="${RUNTIME_DIR}/sentinel.log"
LOCK_DIR="${RUNTIME_DIR}/start.lock"
START_TIMEOUT="${SENTINEL_START_TIMEOUT:-20}"
STOP_TIMEOUT="${SENTINEL_STOP_TIMEOUT:-15}"
API_HOST="127.0.0.1"
API_PORT="${SDN_DEMO_PORT:-18000}"
DASH_PORT="${SDN_DASHBOARD_PORT:-5173}"

usage() {
  cat <<'EOF'
Usage: ./scripts/run_all.sh <command>

Commands:
  start    Start the loopback API and React dashboard in the background
  stop     Gracefully stop only the launcher started by this script
  restart  Stop, then start the managed application
  status   Show managed process identity and API/dashboard readiness
  logs     Show the last log lines; pass -f to follow
  check    Validate dependencies, then run project checks
  help     Show this help

Prerequisites: .venv with project dependencies, Node.js 20.19+ or 22.12+,
and frontend dependencies installed with npm ci. No sudo is used.
Runtime state is stored in var/run-all/ (ignored by Git).
The launcher never starts Mininet, Ryu, attack traffic, or mitigation.
EOF
}

error() { printf 'ERROR: %s\n' "$*" >&2; }

startup_signal() {
  local signal_name="$1" exit_code=130
  [[ "$signal_name" == TERM ]] && exit_code=143
  trap - INT TERM
  if [[ -s "$PID_FILE" ]] && read_pid >/dev/null; then
    printf 'Received %s during startup; stopping the managed application.\n' "$signal_name" >&2
    stop_app || true
  fi
  exit "$exit_code"
}

launcher_matches() {
  local pid="$1" recorded_start current_start cmdline
  [[ -r "/proc/${pid}/stat" && -r "/proc/${pid}/cmdline" ]] || return 1
  recorded_start="$(cat "${RUNTIME_DIR}/launcher.start" 2>/dev/null || true)"
  current_start="$(awk '{print $22}' "/proc/${pid}/stat" 2>/dev/null || true)"
  [[ -n "$recorded_start" && "$recorded_start" == "$current_start" ]] || return 1
  cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
  [[ "$cmdline" == *"apps.project_launcher"* || "$cmdline" == *"scripts/run_project.sh"* ]]
}

read_pid() {
  [[ -s "$PID_FILE" ]] || return 1
  local pid
  pid="$(cat "$PID_FILE")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  launcher_matches "$pid" || return 1
  printf '%s' "$pid"
}

http_ready() {
  local url="$1"
  python3 - "$url" <<'PY'
import sys
from urllib.request import urlopen
try:
    with urlopen(sys.argv[1], timeout=0.8) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception:
    raise SystemExit(1)
PY
}

service_status() {
  local pid="" api=unavailable dashboard=unavailable
  if pid="$(read_pid)"; then printf 'Launcher: running (pid %s)\n' "$pid"; else printf 'Launcher: stopped\n'; fi
  http_ready "http://${API_HOST}:${API_PORT}/health" && api=ready
  http_ready "http://${API_HOST}:${DASH_PORT}/" && dashboard=ready
  printf 'API: %s (http://%s:%s/health)\n' "$api" "$API_HOST" "$API_PORT"
  printf 'Dashboard: %s (http://%s:%s/)\n' "$dashboard" "$API_HOST" "$DASH_PORT"
  [[ "$api" == ready && "$dashboard" == ready ]]
}

start_app() {
  mkdir -p -- "$RUNTIME_DIR"
  if [[ -e "$PID_FILE" ]]; then
    if read_pid >/dev/null; then error "Sentinel is already managed by PID $(cat "$PID_FILE"). Use status or restart."; return 1; fi
    error "stale launcher metadata at $PID_FILE; inspect it and remove only those runtime metadata files if the recorded process is known to be gone"
    return 1
  fi
  if ! mkdir -- "$LOCK_DIR" 2>/dev/null; then error "another start operation holds ${LOCK_DIR}"; return 1; fi
  trap 'rmdir -- "$LOCK_DIR" 2>/dev/null || true' RETURN
  for path in "$ROOT/.venv/bin/python" "$ROOT/apps/frontend/node_modules/.bin/vite" "$ROOT/apps/frontend/package-lock.json"; do
    [[ -e "$path" ]] || { error "missing prerequisite: $path; see ./scripts/run_all.sh help"; return 1; }
  done
  command -v node >/dev/null || { error 'Node.js is required'; return 1; }
  command -v npm >/dev/null || { error 'npm is required'; return 1; }
  command -v setsid >/dev/null || { error 'setsid is required (install util-linux)'; return 1; }
  if ! "$ROOT/.venv/bin/python" -m apps.project_launcher --check; then error 'launcher dependency/port check failed'; return 1; fi
  : >> "$LOG_FILE"
  trap 'startup_signal INT' INT
  trap 'startup_signal TERM' TERM
  cd -- "$ROOT"
  setsid "$ROOT/scripts/run_project.sh" >> "$LOG_FILE" 2>&1 &
  local pid=$! start_ticks="" i
  printf '%s\n' "$pid" > "${PID_FILE}.tmp"
  mv -- "${PID_FILE}.tmp" "$PID_FILE"
  for ((i=0; i<50; i++)); do
    if [[ -r "/proc/${pid}/stat" ]]; then start_ticks="$(awk '{print $22}' "/proc/${pid}/stat")"; [[ -n "$start_ticks" ]] && break; fi
    sleep 0.05
  done
  if [[ -z "$start_ticks" ]]; then error 'launcher exited before process identity could be recorded'; rm -f -- "$PID_FILE"; return 1; fi
  printf '%s\n' "$start_ticks" > "${RUNTIME_DIR}/launcher.start"
  for ((i=0; i<START_TIMEOUT*10; i++)); do
    if ! launcher_matches "$pid"; then error "launcher exited during startup; inspect $LOG_FILE"; rm -f -- "$PID_FILE" "${RUNTIME_DIR}/launcher.start"; return 1; fi
    if http_ready "http://${API_HOST}:${API_PORT}/health" && http_ready "http://${API_HOST}:${DASH_PORT}/"; then
      printf 'Sentinel started. Dashboard http://%s:%s/ · API http://%s:%s/api/v1\n' "$API_HOST" "$DASH_PORT" "$API_HOST" "$API_PORT"
      printf 'Logs: %s\n' "$LOG_FILE"
      trap - INT TERM
      return 0
    fi
    sleep 0.1
  done
  error "startup readiness timed out; requesting graceful cleanup; inspect $LOG_FILE"
  stop_app || true
  return 1
}

stop_app() {
  mkdir -p -- "$RUNTIME_DIR"
  local pid i
  if ! pid="$(read_pid)"; then
    if [[ -e "$PID_FILE" ]]; then error 'stale PID metadata; process identity did not match, leaving any process untouched'; return 1; fi
    printf 'Sentinel is not managed by this launcher.\n'
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  for ((i=0; i<STOP_TIMEOUT*10; i++)); do
    if ! launcher_matches "$pid"; then rm -f -- "$PID_FILE" "${RUNTIME_DIR}/launcher.start"; printf 'Managed launcher stopped; it performed its bounded child cleanup.\n'; return 0; fi
    sleep 0.1
  done
  error "managed launcher PID $pid did not exit within ${STOP_TIMEOUT}s; left it running to avoid orphaning children"
  return 1
}

check_all() {
  cd -- "$ROOT"
  "$ROOT/.venv/bin/python" -m apps.project_launcher --check || return
  npm --prefix apps/frontend run check || return
  npm --prefix apps/frontend test || return
  npm --prefix apps/frontend run build || return
  "$ROOT/.venv/bin/python" -m pytest -q || return
  "$ROOT/.venv/bin/python" -m ruff check . || return
  "$ROOT/.venv/bin/python" -m mypy || return
  "$ROOT/.venv/bin/python" -m compileall -q apps/api networking/ryu src/sdn_defense scripts tests
}

show_logs() {
  local follow=0 api_log dashboard_log path
  [[ "${1:-}" == -f ]] && follow=1
  [[ -f "$LOG_FILE" ]] || { error "no log file at $LOG_FILE"; return 1; }
  local -a files=("$LOG_FILE")
  api_log="$(sed -n 's/^API log: //p' "$LOG_FILE" | tail -n 1)"
  dashboard_log="$(sed -n 's/^Dashboard log: //p' "$LOG_FILE" | tail -n 1)"
  for path in "$api_log" "$dashboard_log"; do
    [[ -n "$path" && -f "$path" ]] && files+=("$path")
  done
  if (( follow )); then tail -n 100 -f -- "${files[@]}"; else tail -n 100 -- "${files[@]}"; fi
}

command="${1:-help}"
case "$command" in
  start) start_app ;;
  stop) stop_app ;;
  restart) stop_app && start_app ;;
  status) service_status ;;
  logs) shift || true; show_logs "${1:-}" ;;
  check) check_all ;;
  help|-h|--help) usage ;;
  *) error "unknown command: $command"; usage >&2; exit 2 ;;
esac
