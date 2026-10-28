# Explainable SDN-Based Network Intrusion Detection System

Research prototype for examining explainable intrusion evidence and bounded defense in a controlled SDN testbed. The repository contains frozen offline ML research, a separate offline application inference model, and a provisional four-feature live anomaly scorer. **A bounded port-scan scenario has now been collected and scored, but the scorer is not an attack classifier; a separate supervised candidate remains unapproved because only three independent runs per class are available. Mitigation remains disabled.**

## Current implementation

- Deterministic local demo API and React/TypeScript/Vite dashboard, with SQLite-persisted sessions, demo events, predictions, and audit records.
- Ryu/OpenFlow 1.3 controller publishes observed datapath/epoch heartbeat state; the API reports `CONNECTED`, `DISCONNECTED`, `STALE`, or unavailable based on that state, never just a listening port.
- Four-value rule-counter feature builder, strict lineage audit, and API poller. A verified benign-only run produced ten source-verified windows; a separate calibration artifact now provides provisional robust anomaly scores and feature-level explanations for fresh eligible windows.
- Offline Stage 5 evaluation scripts and frozen artifacts. A separate opt-in application baseline trainer can create a safe JSON 77-feature offline model under `var/models/`; the 77-feature pipeline is not compatible with the four-feature live schema.
- Existing bounded mitigation policy, Ryu adapter, verifier, lifecycle, expiry, and rollback code. These do not make the dashboard a live defense appliance; demo mode never submits actions.

See [implementation status](docs/implementation-status.md), [limitations](docs/limitations.md), and [tomorrow's review guide](docs/demo-and-review.md).

## Prerequisites

- Python 3.11 or later.
- A modern browser.
- Node.js 20.19+ or 22.12+ and npm (Vite 8); Python 3.11+.
- Optional live SDN validation separately requires an approved isolated environment, root, Mininet, OVS, and the pinned Ryu runtime. See [networking and safety](docs/networking-and-safety.md).

## Install

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev,ml]'
cd apps/frontend && npm ci && cd ../..
```

The demo API itself uses only the Python standard library. `.[dev,ml]` supports repository tests and the offline ML workflow. No credentials are needed. `.env.example` documents configuration names; export selected values in the shell before launching (the launcher does not source `.env`). Set `SDN_DEMO_DATABASE` for a different local SQLite path. `.github/workflows/ci.yml` defines unprivileged CI checks. Python dependency ranges are in `pyproject.toml`; the frontend dependency tree is pinned by `apps/frontend/package-lock.json`.

## Run the local application

Requires Python 3.11+, Node.js 20.19+ or 22.12+, npm, the repository `.venv`, and frontend dependencies. On a fresh checkout, install the project dependencies once (the launcher never reinstalls them during normal use):

```bash
cd ~/Workspace/Projects/Capstone
./scripts/run_project.sh --setup
```

Use the root master launcher to manage the local API and dashboard:

```bash
./scripts/run_all.sh start
./scripts/run_all.sh status
./scripts/run_all.sh logs       # add -f to follow
./scripts/run_all.sh restart
./scripts/run_all.sh stop
./scripts/run_all.sh check
```

The master launcher resolves the repository from its own location, uses the existing Python environment and `npm ci` installation, starts the API before Vite, and waits for both health endpoints. Defaults are loopback API `127.0.0.1:18000` and dashboard `127.0.0.1:5173`. Override ports in the environment, for example `SDN_DEMO_PORT=18001 SDN_DASHBOARD_PORT=5174 ./scripts/run_all.sh start`. The application remains loopback-only. An occupied port causes an actionable error; the launcher never kills the process that owns it.

Launcher PID metadata and supervisor output are stored under ignored `var/run-all/` (`launcher.pid`, `launcher.start`, `sentinel.log`). The Python manager writes per-run API and dashboard logs under ignored `var/logs/`; `logs` displays/follows those along with supervisor output. `stop` sends a signal only to the recorded launcher after checking its process start time and command identity; the existing Python process manager then performs bounded cleanup of its owned API and frontend process groups. Ctrl+C or TERM during startup requests the same managed cleanup; after startup, use `stop` or `restart`. The ordinary launcher never invokes sudo, Ryu, Mininet, OVS, attack traffic, model training, or mitigation. `scripts/run_project.sh` remains the lower-level foreground/setup/check/smoke entry point for development.

Troubleshooting: run `./scripts/run_all.sh status` and `./scripts/run_all.sh logs`; if a port is occupied, choose two free ports with the environment variables above rather than killing an unknown process. If Python or frontend dependencies are missing, run `./scripts/run_project.sh --setup` once. If PID metadata is stale, inspect `var/run-all/launcher.pid` and `launcher.start`, verify that exact process is gone, then remove only those stale metadata files. Open the dashboard as `http://127.0.0.1:5173` or `http://localhost:5173` (both loopback twins are accepted); a different host or port will fail closed. Use `./scripts/run_project.sh --smoke` for the bounded HTTP smoke test.

The dashboard separates historical aggregate experiment results, prepared CSE-CIC-IDS2018 source-label rows, recorded telemetry audit status, model registry entries, offline model predictions, and synthetic demo fixtures. The **Run Offline Inference** page previews a bounded deterministic prefix (1–20 rows) and sends each selected prepared record through the actual hash/schema-checked model route. Predictions persist with source hash, row, model identity, explanation, and audit reference. The Predictions page supports class/source filtering and JSON/CSV export. Prepared prefixes are not representative samples. These offline model outputs are not live detections, calibrated probabilities, or evidence that an attack occurred on a network.

The offline application model is an optional, locally generated JSON artifact under ignored `var/models/`. On a fresh checkout, create it explicitly only if prepared inputs and the optional training dependencies are available:

```bash
./scripts/train_application_model.py
```

This application baseline is not an approved live model and must never receive four-feature rule-counter telemetry. The live anomaly baseline is a separate, hash-verified JSON calibration at `var/models/stage7-live-robust-v1/`, originally calibrated from a verified benign run. New isolated data in `experiments/stage7-telemetry/live-2026-10-28-bounded-scan-07/` through `-09/` contains three verified benign and three bounded h2→h3 port-scan runs. A run-separated logistic candidate reports macro F1 0.8091, benign FPR 0.10 and port-scan FNR 0.2727 on one held-out run per class; it is unapproved and inference-disabled because this evidence is too small. During `live-2026-10-28-integrated-score-10`, the API persisted real anomaly scores while Ryu reported a connected datapath; one port-scan and one benign window exceeded the provisional threshold. This is not validated attack detection, and scores are neither probabilities nor attack labels. Live mitigation remains disabled. The normal launcher never starts networking, Ryu, Mininet, attack traffic, or mitigation.

To calibrate the provisional live baseline from another eligible benign run, first pass the documented isolated-lab preflight, then run the benign-only collector into a new unique output directory. After auditing that run, calibrate into a new model directory (the command refuses overwrite):

```bash
.venv/bin/python scripts/calibrate_live_baseline.py \
  --run-dir experiments/stage7-telemetry/<audited-benign-run> \
  --output-dir var/models/<new-model-directory> \
  --threshold 4.0 --max-gap-seconds 30
```

The active API reads only the configured `var/models/stage7-live-robust-v1` artifact and only scores recent, complete, audited windows for an epoch Ryu currently reports connected. Do not install another baseline there without stopping the API and preserving the existing model artifact. Live scoring readiness does not imply attack detection validity. Mitigation remains disabled.

## API and tests

The local API guide and example responses are in [docs/api/README.md](docs/api/README.md). OpenAPI is not provided by this dependency-light demo API. The API intentionally has no live-operation or mitigation endpoint.

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy
npm --prefix apps/frontend run check
npm --prefix apps/frontend run build
npm --prefix apps/frontend test
.venv/bin/python scripts/smoke_demo.py
```

The smoke script performs bounded loopback HTTP checks against the API and Vite entrypoint, and exercises session create/read/stop/export/audit. It does not launch a browser. Focused API tests run in-process without root or network services. The existing optional system tests are skipped unless explicitly enabled in an approved isolated environment. Do not invoke a live runner without reviewing its safeguards and current gate status.

## Optional SDN work

The existing Stage 2 setup and current Stage 7 evidence are documented in [Stage 2 control plane](docs/architecture/stage2-sdn-control-plane.md), [Ryu setup](docs/architecture/ryu-runtime-setup.md), and [safe networking workflow](docs/networking-and-safety.md). The explicit Ryu listener port is `6653`. Automated demo commands do not start Mininet, Ryu, OVS, attacks, or mitigation.

Before an optional benign collection, run `sudo .venv/bin/python scripts/preflight_stage7_lab.py --ack-isolated-lab`. It is read-only and returns nonzero when privileges, OVS inspection, bridge scope, Ryu runtime, or loopback 6653 gate is not satisfied. Review the output and ensure the OVS bridge inventory is safe before proceeding. The successful run was started with:

```bash
sudo python3 scripts/run_stage7_rule_counter_validation.py \
  --output-dir experiments/stage7-telemetry/<new-unique-run-id> \
  --ryu-manager "$PWD/.venv-ryu/bin/ryu-manager" \
  --wall-timeout-seconds 120
.venv/bin/python scripts/audit_stage7_rule_counter_telemetry.py \
  experiments/stage7-telemetry/<new-unique-run-id>/telemetry.jsonl
```

Use a new output directory every time. This runner sends only bounded ICMP connectivity probes between Mininet h1 and h3. It does not run attacks or enable inference/mitigation. If OVS inspection is denied, ask an administrator to review `ovs-vsctl show`; do not infer isolation from installed tools.

The separately gated mixed collector sends a fixed eight-probe TCP port scan only from isolated h2 to h3 (`10.0.0.3`), at one probe/second for eight seconds. Its parent enforces a 180-second total deadline and verifies cleanup. This command requires explicit operator authorization and a passing read-only preflight; it does not enable mitigation:

```bash
sudo /usr/bin/python3 scripts/preflight_stage7_lab.py --json --ack-isolated-lab
sudo /usr/bin/python3 scripts/run_stage7_telemetry_collection.py \
  --output-dir experiments/stage7-telemetry/<new-unique-output-dir> \
  --ryu-manager "$PWD/.venv-ryu/bin/ryu-manager" \
  --wall-timeout-seconds 180
```

The collector preserves the combined raw telemetry and emits per-run streams. Each stream must independently pass the structural auditor before use. After at least three independent paired collections, the optional builder and trainer are:

```bash
.venv/bin/python scripts/build_stage7_live_dataset.py \
  --run-dir experiments/stage7-telemetry/<verified-run-1> \
  --run-dir experiments/stage7-telemetry/<verified-run-2> \
  --run-dir experiments/stage7-telemetry/<verified-run-3> \
  --output-dir experiments/stage7-live-evaluation/<new-dataset-dir>
.venv/bin/python scripts/train_stage7_live_baseline.py \
  --dataset-manifest experiments/stage7-live-evaluation/<new-dataset-dir>/manifest.json \
  --output-dir var/models/<new-live-candidate-dir>
```

Training output is a research candidate only. It is not registered for inference or live approved until a separately justified independent-run evaluation passes; do not change the registry gate to obtain a green status.

## Troubleshooting

- **Dashboard shows an API error:** use the exact URLs printed by the launcher and inspect the per-run API log. Vite receives the selected API base URL from the launcher environment.
- **A port is busy:** do not stop an unknown process. Set `SDN_DEMO_PORT` and/or `SDN_DASHBOARD_PORT` for `run_all.sh`; the lower-level `run_project.sh` also accepts `--api-port` / `--dashboard-port`. The launcher sets the dashboard API URL and CORS origin for that run.
- **Database is locked:** close other demo processes using the same database or set `SDN_DEMO_DATABASE` to another path.
- **Prepared data is unavailable:** check local ignored dataset files against the Stage 5D frozen manifest. Do not regenerate or rewrite frozen artifacts; unavailable or mismatched files are shown as unavailable.
- **Mininet privilege or Ryu issue:** do not use the demo as evidence of live readiness; review the exact preflight and open gates in networking documentation.

## Safety and limitations

Live mode and mitigation are disabled by default. Do not expose the demo API outside loopback. The synthetic records are segregated from the historical network telemetry and offline datasets. No generic web endpoint accepts shell commands. The active protocol and safety boundaries are authoritative; see `AGENTS.md` and [research protocol](docs/research/research-protocol.md).

The repository contains large private datasets and historical experiment outputs. `.gitignore` excludes the data tree; review all files before any publication. No license is present. A project license decision is required before release. Git metadata is absent in this workspace, so no branch, diff, or clean working-tree state can be asserted.
