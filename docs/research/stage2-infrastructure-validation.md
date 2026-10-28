# Stage 2 Infrastructure Validation

## Scope and research boundary

Stage 2 validates the local SDN control plane needed for later controlled network experiments. It is infrastructure validation only. It provides no evidence for RQ1, RQ2, RQ3, or RQ4 and makes no security, detection, or model-performance claim.

## Validated

- Mininet 2.3.1b4 on Fedora created the controlled three-host topology.
- Open vSwitch 3.6.2 provided the virtual switch; its database was responsive.
- Ryu 4.34 from upstream commit `d6cda4f427ff8de82b94c58aa826824a106014c2` started under Python 3.11 in the isolated `.venv-ryu` environment.
- The OVS switch connected to Ryu over OpenFlow 1.3 and Ryu received switch features.
- The validation harness observed flow statistics and exercised its explicit, reversible test-flow rule.
- Hosts h1 and h3 communicated bidirectionally through the Ryu-controlled OVS switch.
- The validation harness completed cleanly.

## Stage 2 closeout result

Stage 2 infrastructure validation passed on Fedora using Python 3.11, Mininet 2.3.1b4, Open vSwitch 3.6.2, and Ryu 4.34 from pinned upstream commit `d6cda4f427ff8de82b94c58aa826824a106014c2`. The controlled Mininet topology connected successfully to the Ryu controller over OpenFlow 1.3, and bidirectional h1↔h3 forwarding completed with 0% packet loss.

The successful command was:

```bash
RYU_SOURCE_DIR="${RYU_SOURCE_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/sdn-defense/ryu-stage2/d6cda4f427ff8de82b94c58aa826824a106014c2}"
sudo env \
  PATH="$PWD/.venv-ryu/bin:$PATH" \
  PYTHONPATH="$RYU_SOURCE_DIR:$PWD" \
  SDN_STAGE2_RYU_MANAGER="$PWD/.venv-ryu/bin/ryu-manager" \
  /usr/bin/python3 -m networking.ryu.validate_stage2 \
  --log-file /tmp/stage2-ryu.log
```

The harness reported `h1 -> h3`, `h3 -> h1`, `0% dropped (2/2 received)`, and `Stage 2 validation passed.` The local structured log is `/tmp/stage2-ryu.log`; it is a temporary validation artifact and is not committed. Rerun the command above to regenerate it.

An earlier `sudo mn --test pingall` run demonstrated Mininet/OVS forwarding only. Mininet reported that no default OpenFlow controller was found and fell back to an OVS bridge, so that command is not evidence of Ryu integration. The controller integration result above comes from the Stage 2 validation harness.

## Reconstructing the Ryu runtime

The reproducible isolated setup is documented in [Ryu runtime setup](../architecture/ryu-runtime-setup.md) and automated by `scripts/setup_ryu_stage2.sh`. It pins the upstream source commit, keeps Ryu out of the main `.venv`, and does not patch upstream Ryu. The setup script defaults to a user cache location and the command above resolves that checkout without relying on a temporary directory.

The root-run harness must explicitly preserve the controller executable and Python import paths. `sudo` otherwise drops the environment needed to import Ryu. The successful invocation above shows the required `PATH`, `PYTHONPATH`, and `SDN_STAGE2_RYU_MANAGER` values.

## Not validated by Stage 2

Stage 2 did not validate or implement:

- attack generation or attack detection;
- ML, GraphSAGE, novelty/OOD detection, concept drift, or adaptation;
- explanations or explainable risk-aware mitigation;
- automated mitigation policy or security effectiveness;
- dashboard, hardware, Internet-scale behavior, or research hypotheses.

No Stage 2 result should be used as a benchmark or as evidence for any research question. The basic switch observation and test rule validate the control plane only. The test rule is explicit, local, reversible, and not an automatic security action.

## Environment compatibility note

The normal PyPI installation route failed because this legacy Ryu setup hook calls the removed `setuptools.command.easy_install.get_script_args` API. The isolated runtime uses the unmodified upstream source at the pinned commit, a `.pth` import path, and a small `ryu-manager` launcher in `.venv-ryu`. The setup and exact dependencies are recorded in the linked runtime guide. Eventlet emits a deprecation warning; this known warning did not prevent the successful validation.

## Stage 3 boundary

Stage 3 is planned in [Controlled attack scenarios](stage3-controlled-attacks.md). That document is a plan only: no attack generator or attack scenario has been implemented or run as part of this closeout.
