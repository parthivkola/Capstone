# Implementation checklist

This checklist records the current local review build and live-lab gates. It does not authorize privileged networking or revise the research protocol.

| Area | State | Evidence / next step |
|---|---|---|
| Repository and preservation | Done | Workspace, current code paths, data/artifact locations and available environments inspected. Frozen manifest has 160 SHA-256 entries; all 160 match after this sprint. `.git` is an empty/unusable Git directory. |
| Offline baseline | Done | Before edits: 323 passed, 2 opt-in privileged tests skipped. Final: 331 passed, 2 skipped; Ruff, mypy, Python compile, frontend type check, 2 client tests and Vite production build pass. |
| Review application | Implemented and smoke-tested | WSGI API, SQLite, React/Vite, offline inference, persistent sessions/predictions/audit and exports. Alternate-port bounded HTTP smoke passed. Browser interaction was not run. |
| Controller event clock | Implemented; live run unverified | Ryu event timestamps now derive from a UTC anchor plus monotonic elapsed time; delayed scenario `start_at` stays metadata. A configurable maximum feature gap is validated. A newly collected isolated run must be re-audited before claiming resolution. |
| Lab isolation preflight | Implemented; host blocked | Read-only preflight checks privileges, tool versions, OpenFlow 1.3, OVS service/bridge-port inventory, interfaces and loopback port 6653. This host is UID 1000 and OVS inspection returns Permission denied. No lab process was started. |
| Historical telemetry | Invalid/unavailable as training evidence | Six old streams were inspected read-only: three are rejected for backward wall timestamps; three parse but have legacy/incomplete provenance and zero source-verified pairs. Frozen files remain unchanged. |
| Live feature contract | Partial; offline tested | Existing four-feature schema, epoch/provenance audit and fail-closed builder remain. No accepted live feature windows were collected in this sprint. |
| Live-native model and evaluation | Unavailable | No eligible run-labeled dataset or approved artifact exists. Offline 77-feature model remains incompatible and is never invoked for live data. Requires isolated, labeled independent runs and held-out validation. |
| Live API/controller integration | Unavailable | API correctly reports `NOT_MONITORED`; it has no Ryu datapath-status or telemetry-ingest adapter. No port-open shortcut or fake connectivity is used. |
| Mitigation | Disabled | Existing policy/lifecycle/verifier tests remain offline; no real detector result, lab verification, submission, or rollback was produced. |
| HTTP smoke | Passed | `./scripts/run_project.sh --smoke --api-port 18282 --dashboard-port 5282`; actual model inference, API records, session and restart persistence checked. |
| Browser walkthrough | Not verified | No browser automation runtime was available. Manual review remains required for navigation, responsive layout, browser console/network, and the interactive inference workflow. |
| Live validation | Blocked | `./scripts/preflight_stage7_lab.py --ack-isolated-lab` exits 2: effective UID is 1000 and `ovs-vsctl show` cannot access the active system OVS database. |

## Next gates

1. An administrator must inspect OVS bridge ownership (`sudo ovs-vsctl show`) and provide a dedicated isolated lab scope; do not stop the shared OVS service or alter bridges automatically.
2. After the host passes preflight and an approved protocol exists, collect a fresh, benign-only run into a unique output directory and re-audit all provenance/timing.
3. Obtain actual scenario-labeled feature windows from controlled runs; split by independent run, then train/tune on training/validation only and report held-out metrics before approval.
4. Keep live inference and mitigation disabled until model compatibility, lab performance, exact-scope enforcement, independent verification and rollback all pass.
