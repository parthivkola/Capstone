# ADR 007: Separate mitigation submission and confirmation

- **Status:** Accepted
- **Context:** A controller request can be accepted locally while the switch never applies the intended state.
- **Decision:** Record `SUBMITTED` only for submission; require independent observation of exact action and selectors for `CONFIRMED`. Verify absence independently after rollback.
- **Alternatives:** Treat an API success as proof of effect. This cannot establish actual switch behavior.
- **Consequences:** Verifier failure leaves action unconfirmed and requires safe expiry/rollback handling. Demo mode never submits actions.
