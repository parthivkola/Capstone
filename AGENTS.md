# Contributor Rules

## Research integrity

- Do not fabricate experimental results, metrics, datasets, observations, or claims.
- Treat [docs/research/research-protocol.md](docs/research/research-protocol.md) as the authoritative research specification.
- Keep known-class classification, novelty detection, drift evaluation, and live SDN evaluation as separate protocols.
- Do not assume GraphSAGE outperforms Random Forest or another baseline.

## Data and ML controls

- Prevent ML leakage: test data must never influence preprocessing fitting, feature selection, thresholds, hyperparameters, model selection, graph construction, or training.
- Select thresholds and maximum acceptable false-positive operating points using validation data only.
- Keep dataset-specific preprocessing and split manifests explicit; do not blindly merge datasets with different feature or label semantics.
- Make deterministic seeds configurable; record configuration, dataset version, split identity, and software environment for every experiment.
- Do not add ML models in Stage 1.

## Application design

- Keep business logic out of FastAPI routes. Routes, when introduced, may only validate transport data and delegate to application services.
- Integrate external systems through interfaces and adapters. Do not couple domain logic directly to Mininet, OVS, Ryu, GPIO, databases, or third-party SDKs.
- Do not hard-code configuration. Read settings from configuration sources and provide documented defaults only where safe.
- All important functionality requires focused automated tests.
- Do not create FastAPI business logic, React UI, hardware GPIO logic, database schema, Ryu logic, or OpenFlow mitigation in Stage 1.

## Network and mitigation safety

- Network actions require explicit, documented boundaries and authorised test environments.
- Keep Mininet attack scenarios isolated from external networks. Never implement or run attacks outside approved isolated test environments.
- Mitigation must be bounded and reversible: flow-scoped where possible, protected-flow aware, time-limited, logged, and able to roll back.
- Do not implement attacks, Ryu control logic, or OpenFlow mitigation in Stage 1.

