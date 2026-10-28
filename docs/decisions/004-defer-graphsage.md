# ADR 004: Defer GraphSAGE

- **Status:** Accepted
- **Context:** The capstone has not established that graph learning improves performance over simpler baselines, and live data is not ready.
- **Decision:** Do not add GraphSAGE to this implementation pass or assume it outperforms Random Forest.
- **Alternatives:** Add a graph model immediately. This would add complexity without compatible evidence or a validated comparison.
- **Consequences:** First establish a live-native baseline and credible run-level evaluation before considering graph models.
