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

This is an initial adapter corpus, not evidence of coverage across all supported security families.
Copy the selected cases into a disposable explicit application workspace before a campaign; the
installed module never treats its own resources or arbitrary host paths as target authority.
