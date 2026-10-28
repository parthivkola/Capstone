# ADR 001: Ryu/OpenFlow with Mininet and OVS

- **Status:** Accepted
- **Context:** The project needs a controlled SDN environment that emits switch rule-stat observations and supports bounded enforcement verification.
- **Decision:** Reuse the existing Ryu/OpenFlow 1.3 controller and isolated Mininet/OVS testbed.
- **Alternatives:** A different controller, packet-capture-only monitoring, or a cloud/production network. These do not match the existing reproducible rule-counter work and would expand safety scope.
- **Consequences:** Existing controller and testbed work remains reusable. Ryu listener is configured at 6653 due the documented SELinux issue on 16653. Live evidence still requires protocol and integration gates; controller existence does not imply detector readiness.
