# Peritus Module Market

Native **Rust plugins that expand Peritus**. Each module contains an independently
compiled Rust executable, its source, a manifest, and any declared resources. Peritus
does not contain Deep Research's coordinator or evidence rules. Installing a new
compatible plugin does not require rebuilding Peritus.

## Use a module

Requires a Peritus build with the native Rust module host (current `develop`).
Earlier released binaries may not support the executable module manifest yet.

In Peritus, open **Modules** in the browser or enter `/modules` in the terminal.
Refresh the market, install a package, explicitly enable it, then select **Use module**.
The plugin supplies its own action buttons, such as **Start research** and **View report**.
Installation never runs code; selecting an enabled native module launches its executable.
Native code runs as your OS account. Agent access to host tools follows live permissions.

The CLI also supports `peritus modules refresh`, `market`, `install-market ID DIGEST`,
`build-install-market ID SOURCE_DIGEST`, `install DIRECTORY`, `enable ID`, `disable ID`,
`show ID`, and `remove ID`. Fetches use immutable Git commits and verify the complete
declared package or source identity. Updates install disabled; existing saved job bytes
remain retained.

## Available modules

| Module | Code and function |
| --- | --- |
| [Deep Research](modules/deep-research/) | Native Rust planner, gatherer, skeptical source admission, synthesis, final fact-checking, persistent evidence ledger, and report generation. |
| [Red Team](modules/red-team/) | Source-built Rust defensive harness with a durable guided complete campaign, scoped source, class-specific real-interface adapters, receipt-backed cross-adapter attack graphs, copy-only repair replay, and Markdown/JSON/SARIF evidence exports. |

Red Team is deliberately absent from the legacy executable `market.toml`; no generated binary is
committed. Current Linux hosts discover it through the additive `sources.toml`, show **Build and
install**, and compile only after that explicit action. The host pins the clean catalog commit,
source tree, lockfile, toolchain, target, and fixed recipe. Preparation is credential-free;
compilation is offline and bounded; only a fully validated package is atomically installed outside
Git, disabled. Failure or interruption leaves any prior installation selected and usable.

The initial prebuilt artifact and source-build recipe target **Linux x86-64 GNU**. The Rust
source and IPC contract support native platform builds; macOS, Windows, and other architectures
need their own compiled artifact or host recipe. Those platforms are not claimed tested by a
Linux run and receive an explicit unsupported source-build result.

## Build and add a Rust plugin

Install the pinned Rust toolchain, then:

```sh
cargo build --locked --release --jobs 2 -p peritus-deep-research
python3 scripts/package.py deep-research --skip-build
```

Python is a maintainer packaging helper only. Prebuilt modules need no Python, Cargo,
container, or separate provider login. Source-built modules currently require the pinned
Rust toolchain and Bubblewrap available on the Linux host; Peritus owns the actual workflow.

Copy [the native Rust template](templates/rust-plugin/) into `modules/YOUR-NAME/`.
Change its package name, module ID, metadata, and executable resource paths; implement
your feature in Rust. `modules/*` are workspace members. Compile, package, and add an
entry to `market.toml` with the printed digest. This workspace includes the compatible
Rust SDK source in `sdk/peritus-plugin-sdk`; no Peritus checkout is needed to build it.
Read [CATALOG.md](CATALOG.md) for the native ABI and catalog contract.

The older `templates/workflow` data-only template is retained for compatibility with
simple host-interpreted workflows. It is not the native Rust plugin format.
