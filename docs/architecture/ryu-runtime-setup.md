# Reproducible isolated Ryu runtime for Stage 2

This setup reconstructs the Stage 2 controller runtime on Fedora with Python 3.11. It keeps the legacy Ryu dependency in `.venv-ryu/`; it does not install Ryu into the project's main `.venv/`, modify upstream Ryu, or copy its source into the repository.

## Pinned inputs

- Python: 3.11 (the project's Python requirement is unchanged).
- Ryu: 4.34, upstream repository `https://github.com/faucetsdn/ryu.git`, commit `d6cda4f427ff8de82b94c58aa826824a106014c2`.
- Runtime dependencies for a newly created environment: exact versions are in `scripts/ryu-stage2-runtime-requirements.txt`.

The normal PyPI Ryu installation path currently fails because the legacy setup hook uses `setuptools.command.easy_install.get_script_args`, which modern setuptools removed. The setup script obtains the unmodified upstream source at the exact commit and writes the **checkout root** (the directory containing `ryu/`) to a `.pth` file in `.venv-ryu`. The launcher uses `.venv-ryu/bin/python` directly. The check verifies that `import ryu` resolves to the configured pinned checkout. No upstream source edits are applied.

The setup script defaults to a user cache location (`$XDG_CACHE_HOME/sdn-defense/ryu-stage2/<commit>`, or `~/.cache/...` when `XDG_CACHE_HOME` is unset). Set `RYU_SOURCE_DIR` only when selecting another local checkout. No temporary source directory is required.

## Setup and check

From the repository root, after installing Git and Python 3.11:

```bash
scripts/setup_ryu_stage2.sh
scripts/setup_ryu_stage2.sh --check
.venv-ryu/bin/ryu-manager --version
```

The setup script can be configured with `PYTHON_BIN`, `RYU_VENV_DIR`, `XDG_CACHE_HOME`, or `RYU_SOURCE_DIR`. It rejects a source checkout at a different commit or with local modifications. For a new `.venv-ryu`, it installs the pinned runtime requirements. For an existing environment, it leaves installed packages unchanged and only repairs the source path and launcher. `--check` is a no-install validation path and checks the interpreter version, source revision, exact `.pth` target, imported `ryu` module location, and launcher version.

## Root-run Stage 2 validation

The Stage 2 harness runs Mininet through the system Python and requires root. `sudo` does not preserve the isolated controller paths automatically; explicitly pass them:

```bash
RYU_SOURCE_DIR="${RYU_SOURCE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/sdn-defense/ryu-stage2/d6cda4f427ff8de82b94c58aa826824a106014c2}"
sudo env \
  PATH="$PWD/.venv-ryu/bin:$PATH" \
  PYTHONPATH="$RYU_SOURCE_DIR:$PWD" \
  SDN_STAGE2_RYU_MANAGER="$PWD/.venv-ryu/bin/ryu-manager" \
  /usr/bin/python3 -m networking.ryu.validate_stage2 \
  --log-file /tmp/stage2-ryu.log
```

The explicit `PYTHONPATH` includes the source checkout root because the root-run harness launches the Ryu executable with a sudo-managed environment. Use the same `RYU_SOURCE_DIR` configured for setup.

The validated local log path is `/tmp/stage2-ryu.log`. It is not a repository artifact; rerun the command to regenerate it.

## Known runtime warning

Eventlet emits a deprecation warning in this Python 3.11 runtime. It is recorded as a compatibility warning, not suppressed or treated as a security or performance finding. The compatibility work is isolated to Ryu's environment; project code and upstream Ryu source remain unchanged.
