#!/usr/bin/env bash
set -euo pipefail

readonly RYU_VERSION="4.34"
readonly RYU_COMMIT="d6cda4f427ff8de82b94c58aa826824a106014c2"
readonly RYU_REPOSITORY="https://github.com/faucetsdn/ryu.git"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_root="$(cd -- "$script_dir/.." && pwd)"
python_bin="${PYTHON_BIN:-python3.11}"
venv_dir="${RYU_VENV_DIR:-$project_root/.venv-ryu}"
cache_root="${XDG_CACHE_HOME:-$(python3 -c 'import os; print(os.path.expanduser("~/.cache"))')}"
source_dir="${RYU_SOURCE_DIR:-$cache_root/sdn-defense/ryu-stage2/$RYU_COMMIT}"
source_dir="$(realpath -m -- "$source_dir")"
mode="${1:-setup}"

fail() {
  printf 'Ryu Stage 2 setup: %s\n' "$*" >&2
  exit 1
}

check_runtime() {
  [[ -x "$venv_dir/bin/python" ]] || fail "missing $venv_dir/bin/python; run setup first"
  local site_packages
  site_packages="$("$venv_dir/bin/python" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"
  [[ -f "$site_packages/ryu-stage2.pth" ]] || fail "missing Ryu source .pth file"
  [[ -x "$venv_dir/bin/ryu-manager" ]] || fail "missing ryu-manager launcher"
  [[ -d "$source_dir/.git" ]] || fail "missing Ryu source checkout at $source_dir"
  local actual_commit
  actual_commit="$(git -C "$source_dir" rev-parse HEAD)"
  [[ "$actual_commit" == "$RYU_COMMIT" ]] || fail "source commit is $actual_commit, expected $RYU_COMMIT"
  [[ "$(cat "$site_packages/ryu-stage2.pth")" == "$source_dir" ]] || fail "Ryu source .pth does not point to configured checkout $source_dir"
  "$venv_dir/bin/python" -c 'import sys; assert sys.version_info[:2] == (3, 11), sys.version'
  "$venv_dir/bin/python" -c 'import pathlib, ryu, sys; expected = pathlib.Path(sys.argv[1], "ryu", "__init__.py").resolve(); actual = pathlib.Path(ryu.__file__).resolve(); assert actual == expected, f"imported {actual}, expected {expected}"; print("Ryu import OK:", actual)' "$source_dir"
  "$venv_dir/bin/ryu-manager" --version
  printf 'Ryu Stage 2 runtime check passed (Ryu %s, commit %s).\n' "$RYU_VERSION" "$RYU_COMMIT"
}

case "$mode" in
  --check)
    check_runtime
    exit 0
    ;;
  setup)
    ;;
  *)
    fail "usage: $0 [setup|--check]"
    ;;
esac

command -v "$python_bin" >/dev/null || fail "Python 3.11 executable not found: $python_bin"
"$python_bin" -c 'import sys; assert sys.version_info[:2] == (3, 11), sys.version'

if [[ ! -d "$source_dir/.git" ]]; then
  mkdir -p -- "$(dirname -- "$source_dir")"
  git clone --filter=blob:none --no-checkout "$RYU_REPOSITORY" "$source_dir"
  git -C "$source_dir" fetch --depth 1 origin "$RYU_COMMIT"
  git -C "$source_dir" checkout --detach "$RYU_COMMIT"
fi

actual_commit="$(git -C "$source_dir" rev-parse HEAD)"
[[ "$actual_commit" == "$RYU_COMMIT" ]] || fail "existing source at $source_dir has commit $actual_commit, expected $RYU_COMMIT"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || fail "Ryu source checkout is modified; use a clean checkout"

created_venv=false
if [[ ! -x "$venv_dir/bin/python" ]]; then
  "$python_bin" -m venv "$venv_dir"
  created_venv=true
fi
if [[ "$created_venv" == true ]]; then
  "$venv_dir/bin/python" -m pip install --requirement "$script_dir/ryu-stage2-runtime-requirements.txt"
else
  printf 'Using existing Ryu environment without changing installed packages: %s\n' "$venv_dir"
fi

site_packages="$("$venv_dir/bin/python" -c 'import sysconfig; print(sysconfig.get_path("purelib"))')"
printf '%s\n' "$source_dir" > "$site_packages/ryu-stage2.pth"
cat > "$venv_dir/bin/ryu-manager" <<'LAUNCHER'
#!/usr/bin/env bash
set -euo pipefail
launcher_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec "$launcher_dir/python" -c 'from ryu.cmd.manager import main; main()' "$@"
LAUNCHER
chmod +x "$venv_dir/bin/ryu-manager"

check_runtime
