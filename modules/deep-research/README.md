# Deep Research — native Rust plugin

The implementation is in `src/coordinator.rs`, `src/ledger.rs`, and `src/definitions.rs`.
`src/main.rs` is the native IPC executable. `workflow.toml` is internal configuration
compiled into this plugin; Peritus does not interpret it or implement these stages.

Select **Use module** and enter a research topic, or send:

```text
/module peritus.deep-research YOUR QUESTION
```

The planner saves a scope and any material clarifications. Review **View plan**, revise
when needed, and select **Start research**. Preparation has no network tools. Start
binds the exact plan digest; resume cannot silently approve a plan.

The Rust coordinator then runs a gatherer, an independent skeptic, a synthesis agent,
and a final skeptic pass. Original-source passages, claim-specific admission decisions,
independence chains, uncertainty, report versions, and exact-report checks persist in
private plugin state. Blogs and generated summaries are discovery leads, not support.
Synthesis sees admitted/qualified evidence, and the final skeptic must inspect the
actual report and reread its cited passages. Structural checks support this process;
they cannot guarantee semantic truth. Honest insufficient-evidence reports are valid.

Actions include plan, revise, status, sources, report, resume, and Use in Design.
Stop uses Peritus's normal control. Completed stages survive daemon restart. Show and
source lists are paged; following a continuation does not start a new research job.
Use in Design attaches the exact checked report as reference without launching coding.

Build from this repository root with `cargo build --locked --release --jobs 2 -p
peritus-deep-research`; package with `python3 scripts/package.py deep-research --skip-build`.
The supplied executable is Linux x86-64 GNU. Other native targets require their own
artifact. Provider access reuses Peritus; no separate research API account is required.
The native web reader's unsupported PDF/scanned/script-generated content remains a
limitation; the plugin must report it, not fabricate extracted evidence.
