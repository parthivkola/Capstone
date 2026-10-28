# Limitations and unsupported claims

- The new CSE-CICFlowMeter application model is a sampled offline binary baseline only. It is not a reproduction of frozen Stage 5 outputs, is not representative of all dataset records, and has no calibrated confidence claim.
- No approved live-native detector exists for the four OpenFlow rule-counter features. The 77-feature offline model is incompatible with that schema and is never used for live inference.
- Existing telemetry artifacts are historical and incomplete or invalid under their audit; no live telemetry was collected in this sprint.
- The dashboard and API are locally runnable and HTTP-smoke-tested, but no browser instance was available for console, responsive, navigation, and visual verification.
- The demo API is standard-library WSGI with SQLite, not FastAPI. It has no authentication or OpenAPI document and must remain loopback-only.
- Demo sessions are synthetic illustrative fixtures and cannot call mitigation. Live controller and mitigation integration were not exercised.
- Existing Mininet/Ryu/OVS integration and bounded runner tests do not establish live topology or enforcement readiness. No privileged networking was performed.
- The optional offline trainer scans and hash-verifies prepared dataset files and can take several minutes. It is never invoked on startup. Model output under `var/models/` is local/ignored and must be reviewed before distribution.
- Historical metrics remain historical. The source/distribution-shift experiment is not proof of temporal or concept drift, and novelty-detection results remain weak.
- Browser automation and GitHub CI were not run in this environment. The workflow file was updated but not executed on GitHub.
- The workspace `.git` directory is empty, so no repository history or clean diff can be claimed. No project license has been chosen, and dataset redistribution terms require review.

Before live deployment, complete source-authenticated telemetry collection and timing policy, train and independently validate a separate live-native model, assess uncertainty and operating-point errors, integrate evidence-aware policy, and conduct authorized isolated mitigation verification with independent rollback evidence.
