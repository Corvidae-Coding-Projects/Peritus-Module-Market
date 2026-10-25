# Stateful workflow and concurrency twins

These source fixtures are launched only in a module-owned target runtime inside a disposable Linux worker. Both twins
offer a small approval-and-charge workflow with a balance of 100, a two-charge quota, stable
request identities, cancellation, simulated worker crash/recovery, and a deterministic two-worker
schedule. The vulnerable twin intentionally permits unapproved and cancelled charges, duplicate
effects, quota overflow, partial crash commits, and a concurrent double commit. The safe twin
rejects or suppresses each hostile sequence while preserving create, approve, charge, and cancel.

The adapter reads the copied state file itself before and after every action. Fixture response text
cannot create a finding. Model-proposed invariants are retained as leads and never promoted to
documented requirements by the fixture or adapter.
