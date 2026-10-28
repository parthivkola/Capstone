# ADR 013: React dashboard and a safe offline inference artifact

- Status: Accepted for local review application.
- Date: 2026-10-28.

## Context

The static dashboard provided little structure for the growing source/model contract. Historical evaluation artifacts were not executable weights, and the repository had no approved live-native model. Prepared labeled Stage 5D records existed with a frozen source split and hashes.

## Decision

Use React + TypeScript + Vite for the local interface and retain the standard-library WSGI API. Add an explicit optional offline application trainer based on LogisticRegression and train-only StandardScaler; persist coefficients/preprocessing as allowlisted JSON under ignored `var/models/`. Verify manifest hash, feature schema, ordering and dimensions before inference. Keep live inference unavailable.

## Alternatives considered

- Keep the static page: rejected because the data/model interface needed reusable typed application views.
- Load historical JSON as a model: rejected because it contains evaluation summaries, not estimator weights.
- Load arbitrary pickle/joblib: rejected due to executable serialization risk and missing artifact provenance.
- Adapt 77 offline features to four OpenFlow counters: rejected as a semantic/schema mismatch.
- Train automatically on application startup: rejected because it makes startup nondeterministic and mutates runtime artifacts.

## Consequences

The dashboard requires Node/npm setup. A new offline baseline can serve real inference when its application artifact exists; new checkouts can start without it and report unavailable. Displayed performance is limited to the explicitly documented sampled source split. The model is never live-eligible, and no claim about unknown attacks or calibrated confidence is made. Browser verification remains pending where no browser is available.
