# Safe workflow/state twin

`application.py` supervises `../shared-service.py` in safe mode, implementing the same legitimate
workflow while enforcing documented invariants across retries, cancellation, crash recovery, quota,
and the deterministic concurrent schedule.

[Parent map](../AGENTS.md).
