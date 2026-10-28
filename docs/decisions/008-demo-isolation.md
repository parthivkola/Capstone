# ADR 008: Keep synthetic demo isolated from live evidence

- **Status:** Accepted
- **Context:** A review UI must be useful without privileged networking or a trained model while avoiding fabricated live status.
- **Decision:** Store demo sessions separately as explicitly synthetic local records; the API reports controller, telemetry, detector, and mitigation unavailable/disabled. The dashboard calls only demo/read routes and has no mitigation operation. Demo HTTP smoke uses temporary storage and loopback-only dynamically selected ports.
- **Alternatives:** Feed synthetic events through the live evidence path or present them as predictions. This would contaminate evidence and mislead reviewers.
- **Consequences:** The demo works without Mininet or external downloads. It demonstrates UI and persistence only, not detection or enforcement.
