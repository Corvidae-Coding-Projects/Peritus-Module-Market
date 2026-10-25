# Red Team real-interface corpus

These MIT-licensed programs are deliberately small, genuine executable targets for the
`linux.canary-disclosure.v1` interface. The host launches each file as the selected application,
passes a private canary path plus literal attacker input, and evaluates the actual stdout bytes.
The target cannot select or replace the evaluator.

`known-disclosure` is a described vulnerable/safe pair. `unknown-diagnostic` is intended for
source-led unknown-discovery exercises without disclosing the trigger in the campaign prompt.
`adversarial` contains forged-success, prompt-injection, unrelated-crash, containment-boundary,
deadline, descendant, memory, process, and storage-pressure controls. They exercise negative
evidence, host-owned oracle integrity, finite resources, cancellation, cleanup, and unavailable
effect boundaries without granting the target authority over the verdict.

`identity-access` contains interface-compatible vulnerable and safe multi-user services for the
Phase 15 host-private identity campaign. Both accept the same real HTTP operations; the vulnerable
twin violates authentication, role, tenant, ownership, and session-lifecycle rules, while the safe
twin enforces the pinned policy. Credentials are generated from laboratory-private material and
never belong in module state, provider context, reports, or replay bundles.

`file-parser` contains matched Phase 16 filesystem, archive, parser, and native-child-fault twins.
`workflow-state` contains matched Phase 17 approval/accounting services whose real state transitions
exercise duplication, replay, retry, cancellation, quota, crash recovery, and a deterministic
two-worker schedule. `boundary-authority` contains matched Phase 18 applications for host-private
DNS/HTTP/TLS peers, denied routable destinations, TLS trust policy, contained privilege, and
delegated-authority cases. In all families the host observes effects independently of target text.

This is an adapter corpus, not evidence of coverage across all supported security families.
Copy the selected cases into a disposable explicit application workspace before a campaign; the
installed module never treats its own resources or arbitrary host paths as target authority.
