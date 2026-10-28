# Local demo API

The review API is implemented by `apps/api/demo_app.py` using Python's WSGI and SQLite standard library. It binds only to loopback. It does not provide arbitrary process execution or mitigation routes. Live endpoints report actual Ryu status and read-only persisted provisional anomaly scores; they do not control the network. JSON responses are returned with `Cache-Control: no-store`.

Start the full application with `./scripts/run_all.sh start`; defaults are API `http://127.0.0.1:18000` and dashboard `http://127.0.0.1:5173`. Use `./scripts/run_all.sh stop` to shut down its owned processes. The API allows one configurable loopback origin via `SDN_DEMO_CORS_ORIGIN`; non-loopback origins are rejected. The launcher passes the selected API base URL to Vite and configures CORS for the chosen dashboard origin. For direct API development, `./scripts/run_project.sh` remains available. Port 8000 is not used by default.

Versioned routes use JSON envelopes and errors of the form `{"error":{"code":"...","message":"...","request_id":null}}`. List routes accept `limit` (1..200) and `offset` (>=0) and return `items` plus a `page` object.

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | API readiness; live network and mitigation disabled |
| GET | `/api/v1/status` | Actual local mode, controller, telemetry and inference availability |
| GET/POST | `/api/v1/sessions` | List sessions or create a synthetic demo session |
| GET | `/api/v1/sessions/{id}` | Session and its records |
| POST | `/api/v1/sessions/{id}/stop` | Stop session and audit transition |
| GET | `/api/v1/sessions/{id}/events` | Paginated synthetic events |
| GET | `/api/v1/sessions/{id}/audit` | Paginated session audit events |
| GET | `/api/v1/sessions/{id}/export` | JSON export with provenance designation |
| GET | `/api/v1/detections` | Persisted real offline model predictions; empty if none |
| GET | `/api/v1/datasets` | Registered historical/raw/prepared source summary |
| GET | `/api/v1/datasets/{id}/preview?file={file}&limit=8` | Hash/schema-verified prepared row prefix |
| GET | `/api/v1/experiments` | Historical aggregate results, not detections |
| GET | `/api/v1/experiments/{id}` | Historical result records selected by experiment/source ID |
| GET | `/api/v1/telemetry/audits` | Recorded telemetry audit metadata |
| GET | `/api/v1/models` | Deployable, unavailable and historical-only registry entries |
| GET | `/api/v1/models/{id}` | One registry entry |
| GET | `/api/v1/models/{id}/health` | Hash/schema load status |
| GET | `/api/v1/inference/schema` | Offline 77-feature input and separate live four-feature observation schemas |
| POST | `/api/v1/inference/predict` | Execute actual compatible offline model if installed |
| GET | `/api/v1/live/status` | Ryu heartbeat/datapath status, calibration health, freshness, current eligible windows and readiness |
| GET | `/api/v1/live/detections` | Persisted once-only four-feature anomaly scores with evidence and explanation |
| GET | `/api/v1/live/ledger` | Persisted live scoring and sustained-change ledger events |
| GET | `/api/v1/audit` | Combined, timestamp-ordered persisted demo and inference audit log (paginated across both tables) |

Inference request shape:

```json
{"request_id":"optional-id","model_id":"cse-cicflowmeter-binary-logistic","feature_schema":"cse-cicflowmeter-77-v1","feature_order":["ordered feature names from /inference/schema"],"features":{"named feature":0.0},"source":{"source_type":"UNSPECIFIED"}}
```

The actual request must contain all 77 finite numeric fields in exact order. For `LABELED_DATA`, the server accepts a registered file ID and row number 1..20, rereads and verifies that row, compares all submitted values, and obtains the label and hash server-side. It does not persist raw feature values. The React Run Offline Inference workspace calls this route once per selected row, sequentially, and displays progress; each successful response is already persisted and auditable if a later row fails. The client bounds a run to 20 rows. A missing/incompatible model returns HTTP 503; invalid schemas/inputs return HTTP 422. The live model ID is rejected.

Paginated collections accept `limit` (1..200) and `offset` (>=0). The UI follows page metadata up to a 10,000-record in-memory safety limit; exceeding the bound is surfaced as an error rather than silently truncated. Prediction JSON/CSV exports include persisted records currently loaded by that bounded collection workflow.

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/health` | Process readiness and disabled live component flags |
| GET | `/api/status` | Actual demo mode; controller disconnected and live telemetry/detection unavailable |
| POST | `/api/demo/sessions` | Create deterministic synthetic scenario examples; accepts `{}` only |
| GET | `/api/demo/sessions/{id}` | Retrieve one persisted synthetic session and its events |
| POST | `/api/demo/sessions/{id}/stop` | Stop the local demo session and append an audit entry |
| GET | `/api/demo/sessions/{id}/export` | Export one persisted session, its events and its own audit lifecycle as JSON |
| GET | `/api/runs` | List persisted demo sessions |
| GET | `/api/events` | List persisted demo events; optional `?run_id=<uuid>` |
| GET | `/api/audit` | List demo session audit entries |
| GET | `/api/models` | Explicit live model unavailability and offline/live separation |
| GET | `/api/data-sources` | Summary of historical results, prepared labels, telemetry, raw files and synthetic fixtures |
| GET | `/api/historical-results` | Exact aggregate results from allowlisted Stage 5 JSON artifacts with source hashes and context |
| GET | `/api/dataset-sources` | Stage 5D prepared files, manifest hashes/schema/counts and availability |
| GET | `/api/dataset-preview?source=cse-cic-ids2018-stage5d&file=<source-file>&limit=8` | Validated deterministic prefix of original labeled records; `prediction` is always null |
| GET | `/api/telemetry-runs` | Historical telemetry file hashes, recorded run metadata and structural provenance audit status |

Example:

```bash
curl -s http://127.0.0.1:18000/api/status
curl -s -X POST -H 'Content-Type: application/json' -d '{}' http://127.0.0.1:18000/api/demo/sessions
curl -s http://127.0.0.1:18000/api/historical-results
```

`/api/v1/status` identifies the UI mode as `DEMO`, while controller state is independently sourced from the Ryu heartbeat (`CONNECTED`, `DISCONNECTED`, `STALE`, `INVALID`, or `NOT_MONITORED`). Live scoring status is `PROVISIONAL_ANOMALY_SCORING` only when a compatible baseline and connected controller are present; telemetry freshness is separately reported. The score records are `source_type: LIVE`, refer to the actual audited telemetry file hash and source snapshot IDs, and contain no attack class or probability. A created demo session is persisted in SQLite; each synthetic event remains explicitly `SYNTHETIC_FIXTURE` with unavailable classification, null confidence, and no feature vector.

There is no OpenAPI document: this deliberately retained WSGI application uses Python's standard library. This local endpoint surface is not authenticated and must not be exposed off-host. It contains no sensitive actions.
