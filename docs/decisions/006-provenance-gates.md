# ADR 006: Require provenance and collection completeness

- **Status:** Accepted
- **Context:** Counter snapshots can be incomplete, stale, reset, cross-run, or associated with a replaced datapath.
- **Decision:** Require complete collections, matching run/epoch/rule identity, valid timing, and auditable source lineage before feature construction.
- **Alternatives:** Impute missing evidence or trust caller-supplied booleans. These can create unsupported features.
- **Consequences:** Invalid/ambiguous input abstains. Synthetic tests support logic but do not prove the live source stream; the source integration gate remains open.
