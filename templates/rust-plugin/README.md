# Native Rust plugin template

Copy this directory to `modules/YOUR-NAME/`. Rename `peritus-example-counter`,
`example.counter`, binary resource paths, and display metadata consistently.
The market workspace includes `modules/*`; the relative SDK dependency then resolves.

The sample implements Unicode text statistics in Rust. `count TEXT` runs native
code directly. `ask TEXT` requests Peritus's writer model with a new `text_count`
function implemented by this plugin. It demonstrates adding code and model tools
without rebuilding or hardcoding the feature in Peritus.

Build with `cargo build --release --jobs 2 -p YOUR-PACKAGE`, package using
`scripts/package.py YOUR-NAME`, install the directory with `peritus modules install`,
and explicitly enable it. The executable communicates through the existing SDK's
framed IPC; the generic service DTOs are in `sdk/peritus-plugin-sdk/src/module.rs`.
