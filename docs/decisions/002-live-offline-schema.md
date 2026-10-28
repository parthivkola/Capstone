# ADR 002: Keep live rule counters separate from offline flow features

- **Status:** Accepted
- **Context:** Offline datasets provide CICFlowMeter or dataset-specific predictors; live telemetry consists of OpenFlow rule counters.
- **Decision:** Version and validate the live-native four-feature schema independently.
- **Alternatives:** Map or impute offline fields from counters. The compatibility audit found no fully derivable offline feature set from the four live values and semantics differ.
- **Consequences:** A separate live-native data collection and evaluation is required. No cross-schema performance claim is possible. Missing values remain unavailable.
