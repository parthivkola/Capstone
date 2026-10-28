# Stage 2 System Validation

The root-required, local-only Stage 2 system validation is:

    RYU_SOURCE_DIR="${RYU_SOURCE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/sdn-defense/ryu-stage2/d6cda4f427ff8de82b94c58aa826824a106014c2}"
    sudo env \
      PATH="$PWD/.venv-ryu/bin:$PATH" \
      PYTHONPATH="$RYU_SOURCE_DIR:$PWD" \
      SDN_STAGE2_RYU_MANAGER="$PWD/.venv-ryu/bin/ryu-manager" \
      /usr/bin/python3 -m networking.ryu.validate_stage2 \
      --log-file /tmp/stage2-ryu.log

It is intentionally not part of ordinary unit-test execution. It requires active Open vSwitch, Mininet, and Ryu, and it must be run only on an isolated local development host. The `PATH` and `PYTHONPATH` values are explicit because sudo otherwise drops the `.venv-ryu` launcher/source import path. See [Ryu runtime setup](../../docs/architecture/ryu-runtime-setup.md) for environment reconstruction. The Stage 2 result and its evidence boundary are recorded in [infrastructure validation](../../docs/research/stage2-infrastructure-validation.md).
