# ADR 005: Preserve weak novelty results as negative evidence

- **Status:** Accepted
- **Context:** Existing Isolation Forest and RF open-set results show negligible unknown recall/F1.
- **Decision:** Preserve these outcomes and do not market the system as a successful unknown-attack detector.
- **Alternatives:** Emphasize accuracy or omit failures. That would obscure severe false-negative behavior.
- **Consequences:** Review materials foreground per-class and false-negative metrics and explicitly state limitations.
