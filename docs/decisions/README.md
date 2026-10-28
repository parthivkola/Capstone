# Architecture decision records

| ADR | Decision | Status |
|---|---|---|
| [001](001-ryu-mininet.md) | Ryu/OpenFlow and Mininet/OVS | Accepted |
| [002](002-live-offline-schema.md) | Keep rule-counter and CICFlowMeter features separate | Accepted |
| [003](003-no-offline-model-reuse.md) | Do not reuse offline RF for live data | Accepted |
| [004](004-defer-graphsage.md) | Defer GraphSAGE | Accepted |
| [005](005-novelty-results.md) | Do not claim novelty success | Accepted |
| [006](006-provenance-gates.md) | Provenance/completeness gate evidence | Accepted |
| [007](007-mitigation-verification.md) | Separate submission from confirmation | Accepted |
| [008](008-demo-isolation.md) | Isolate demo from live networking | Accepted |
| [009](009-review-stack.md) | Dependency-light review API/UI | Provisional for review demo |
| [010](010-supervised-sdn-runner.md) | Parent-supervise blocking Mininet worker | Accepted; live integration unverified |
| [011](011-artifact-backed-dashboard.md) | Display existing project artifacts with provenance | Accepted for local review |
| [012](012-loopback-review-launcher.md) | Start review API and dashboard with one loopback command | Accepted for local review |
| [014](014-live-detection-approval-gate.md) | Keep live detector gated until rule-counter evidence passes | Accepted; gate remains closed |
| [015](015-monotonic-telemetry-timestamps-and-lab-preflight.md) | Monotonic event timestamps and read-only fail-closed lab inspection | Accepted; lab gate remains closed on current host |
