# Vulnerable workflow/state twin

`application.py` supervises `../shared-service.py` in vulnerable mode, deliberately enabling the
Phase 17 state, retry, crash-atomicity, quota, approval, cancellation, and concurrency defects.
Change it only together with the safe twin and host oracle contract.

[Parent map](../AGENTS.md).
