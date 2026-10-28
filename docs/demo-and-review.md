# Demo and academic-review handover

## Start and stop

Install once when needed:

```bash
cd ~/Workspace/Projects/Capstone
./scripts/run_project.sh --setup
```

Then start both services with:

```bash
./scripts/run_all.sh start
```

Open the dashboard URL printed by the launcher (`http://127.0.0.1:5173` or the equivalent `http://localhost:5173` loopback twin). Manage it with `./scripts/run_all.sh status`, `logs`, `restart`, and `stop`. Default API URL is `http://127.0.0.1:18000/api/v1`. Alternate ports: `SDN_DEMO_PORT=18081 SDN_DASHBOARD_PORT=5181 ./scripts/run_all.sh start`. The launcher sets Vite's API base and API CORS origin from those values; both `127.0.0.1` and `localhost` on that dashboard port are accepted.

The launcher checks ports before starting and never kills a listener it did not start. `scripts/run_project.sh` remains available for foreground setup/check/smoke operations; normal managed startup uses `scripts/run_all.sh`.

## What to show

1. Overview: DEMO MODE label. The API reports controller state from Ryu's heartbeat and datapath registry. With no fresh controller it reports `STALE`; with a fresh heartbeat but no datapaths it reports `DISCONNECTED`; with no publisher it reports `NOT_MONITORED`.
2. Project data: nine historical experiment result rows with source-artifact hashes; seven prepared Stage 5D CSE-CIC-IDS2018 files; sampling notice explains that preview is a deterministic file prefix, not representative.
3. Models: the offline application baseline is loadable only if its local `var/models` JSON and manifest are present and hash-compatible. The four-feature robust anomaly scorer is provisional. A separate logistic candidate is shown as `TRAINED_UNAPPROVED_PRELIMINARY`, with inference disabled. A fresh clone will not contain ignored generated model artifacts unless restored locally.
4. Optional offline inference: select a prepared file, preview the first records, and run inference for row 1 if the model registry says inference is enabled. The result shows its separate source label, persisted prediction, uncalibrated sigmoid score, source provenance and model explanation. This is offline inference, not live detection.
5. Start a demo session: six `SYNTHETIC_FIXTURE` illustrative scenarios appear with classification unavailable and null confidence. These are not attacks or detections.
6. Refresh, inspect Audit log, stop the session and export the JSON. The session/event/audit data persists in SQLite.
7. Mitigation page: demo actions are disabled and no enforcement or verification is claimed.

## Verified live collection and scoring evidence

The read-only lab preflight passed: Mininet 2.3.1b4, OVS 3.6.2, Ryu 4.34, OpenFlow 1.3, loopback port 6653 free, and an empty OVS bridge inventory. The topology is fixed to h1/h2/h3 behind s1, with no host uplink.

Three independent paired collections (`live-2026-10-28-bounded-scan-07` through `-09`) each ran six successful bounded benign ICMP probes and eight fixed TCP connection probes from h2 to isolated h3/10.0.0.3 at 1/sec. Every scenario's run-scoped telemetry passed `AUDIT_COMPLETE`, had zero rejected source pairs, and cleanup was verified. They yielded 30 benign and 43 bounded port-scan windows. Dataset `experiments/stage7-live-evaluation/live-2026-10-28-initial-run-split-02/` assigns complete run IDs to train/validation/test and preserves feature rows, run journals, scenario labels and SHA-256 provenance.

The separate logistic candidate in `var/models/stage7-live-logistic-preliminary-03/` has a one-run-per-class held-out confusion matrix `[[9, 1], [3, 8]]`, macro F1 0.8091, benign FPR 0.10 and port-scan FNR 0.2727. Its threshold 0.11526 was selected on validation runs subject to a 10% benign-FPR constraint. A trusted-local artifact reload reproduced the first held-out decision score. The model remains unapproved and inference-disabled because the independent-run evidence is too small for an attack-detection claim.

With the API running during collection `live-2026-10-28-integrated-score-10`, the real Ryu datapath was observed and 10 benign and 10 port-scan windows were persisted with source IDs and explanations. One scan window was `UNUSUAL` (score 6.3022, threshold 4.0; packet-rate deviation +6.3022 robust units); one benign window also exceeded the same threshold. Thus the operational pipeline demonstrated source-linked anomaly scoring and also a false alert. It did not demonstrate validated attack detection. The API was restarted and records remained persisted. The original calibrated scorer is still benign-reference-only.

While the API is running, inspect `/api/v1/live/status`, `/api/v1/live/detections`, and `/api/v1/live/ledger` on its configured local API port. A stopped controller makes current readiness unavailable while already persisted scores remain readable. Live mitigation was not attempted and remains disabled.

## Optional offline model training

The training workflow was run during this sprint with a deterministic cap of 100 examples per binary class per source. It wrote only `var/models/cse-cicflowmeter-binary-logistic-v1/`. The new application baseline used five sources for training, Wednesday 14-Feb as validation and Friday 23-Feb as held-out test, with exact sampled duplicate removal. Test sample support was 99 benign and 95 intrusion: accuracy 0.7784, macro F1 0.7782, benign FPR 0.2121, attack FNR 0.2316. Sampling is not representative; this is not a reproduction of frozen research. The sigmoid output was not separately calibrated. To opt in on another checkout, run `./scripts/train_application_model.py`; it refuses to overwrite an existing output directory and scans/hashes the prepared files.

## Browser checklist and verification limits

The connected browser-control environment reported that no browser instance is available. Browser-level verification was not performed. On Fedora, use Firefox or another local browser:

1. Run the launcher and open its printed dashboard URL.
2. In Developer Tools Network/Console, verify `/api/v1/status`, sessions, datasets, experiments, telemetry, models, inference schema, detections and audit requests return valid JSON without 404s.
3. Navigate all seven pages, refresh, resize to mobile width, and verify the navigation and tables remain usable.
4. Confirm a missing API or stopped API shows a clear error, not empty successful content.
5. Start, reload, stop, and export a demo session; inspect synthetic markers and timestamps in the exported JSON.
6. If offline model is loadable, run inference on a prepared row and verify prediction/audit persistence after refresh. Never interpret it as a live prediction.
7. Verify mitigation is disabled.

Evidence completed here: Vite production build passed; the React/Vite frontend and real WSGI API were started together through the launcher on alternate ports and health/status/root requests succeeded. `scripts/smoke_demo.py` exercised session creation, event retrieval, stop, export, audit and synthetic designation over HTTP. The full browser flow, browser console, and responsive rendering remain unverified. Benign-only Mininet/Ryu/OVS rule-counter runs passed structural provenance audit and independently verified cleanup; the API poller scored ten windows from a connected run. No attack traffic or mitigation was run.

## Final check record (2026-10-28)

- `.venv/bin/python -m pytest -q`: **363 passed, 2 skipped**. Skips are privileged opt-in Mininet/OVS/Ryu enforcement suites.
- `.venv/bin/python -m ruff check .`: passed.
- `.venv/bin/python -m mypy`: passed, 118 source files.
- `npm --prefix apps/frontend run check`: passed.
- `npm --prefix apps/frontend test`: 2 passed; API client success and 404 behavior.
- `npm --prefix apps/frontend run build`: passed with Vite 8.3.3.
- `.venv/bin/python -m compileall -q apps scripts src networking services ml tests`: passed.
- `./scripts/run_project.sh --check`: passed; actual offline model load/hash and provisional live baseline status reported separately.
- `.venv/bin/python -m compileall -q apps/api networking/ryu src/sdn_defense scripts`: passed. Mixed collector `--help` works under both `.venv` and `/usr/bin/python3`.
- `./scripts/run_project.sh --smoke`: passed at default ports; API and React/Vite entrypoint responded over HTTP, and offline inference was exercised on a hash-verified prepared CICFlowMeter row. This is not browser verification.
- Read-only isolated-lab preflight: passed. Runs `-07` to `-10` each passed independent per-scenario provenance audit and cleanup verification. API-integrated `-10` persisted one unusual scan window and one unusual benign window.
- Frozen manifest: **160 unchanged, 0 mismatch** versus the before-sprint manifest.
- `npm install --package-lock-only --ignore-scripts` reported **0 vulnerabilities**. GitHub CI was not run.

## Likely questions

- **Is this live intrusion detection?** The live path consumes actual four-feature OpenFlow windows and emits explainable robust deviation scores. Three controlled port-scan runs and a tiny run-separated supervised evaluation now exist. The candidate remains unapproved because only one held-out run per class supports the metrics, and the robust scorer produced a benign false alert. The offline 77-feature CICFlowMeter model is not used live.
- **Why are historical metrics shown?** They are aggregate outputs from existing artifacts and include their source hashes and contexts; they are not event-level predictions.
- **Does it detect unknown attacks or arbitrary attacks?** No. The controlled label is only the bounded fixed port-scan workload; SYN flood and other scenarios were not evaluated.
- **Does high confidence mean calibrated probability?** No. The logistic sigmoid score is not calibration-validated.
- **Can it block traffic?** The demo has no mitigation action endpoint. Separate mitigation modules require authorization and independent OVS verification; they were not run.
- **Was the UI browser-tested?** No browser instance was available. Actual API/Vite HTTP integration passed, which is weaker evidence than an interactive browser test.
