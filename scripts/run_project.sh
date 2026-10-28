#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
cd -- "${PROJECT_ROOT}"

if [[ -e "${PROJECT_ROOT}/.venv" ]]; then
  if [[ ! -x "${PROJECT_ROOT}/.venv/bin/python" ]]; then
    echo "ERROR: .venv exists but .venv/bin/python is missing. It was not modified." >&2
    exit 1
  fi
  PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"
elif command -v python3.11 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3.11)"
elif command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="$(command -v python3)"
else
  echo "ERROR: Python 3.11 or later is required." >&2
  exit 1
fi

if ! "${PYTHON_BIN}" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
  echo "ERROR: ${PYTHON_BIN} is older than Python 3.11. It was not modified." >&2
  exit 1
fi

exec "${PYTHON_BIN}" -m apps.project_launcher "$@"
