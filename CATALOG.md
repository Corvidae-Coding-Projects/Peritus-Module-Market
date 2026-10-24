# Native Rust module contract

`market.toml` schema 1 lists independent modules with stable `id`, display `name`,
`version`, `description`, repository-relative `path`, exact lowercase SHA-256 package
`digest`, and optional `tags`. Peritus resolves `main` once to a commit, fetches only
that commit's catalog and declared package resources, then verifies the package.

A native `module.toml` has `schema = 1`, identity/display metadata, `resources`, and
`[code]` with `abi = 1`, `tools`, and `[code.artifacts]` mapping native target triples
to executable resource paths. Native modules declare no host-interpreted roles or
stages. Versions use three numeric components representable as unsigned 16-bit values.
All resources are safe relative regular files. The digest binds canonical manifest
serialization and every sorted declared resource path and byte, including the executable.
See `scripts/package.py`. Cross-check its digest using `peritus modules install DIRECTORY`.

## Native execution

A separately compiled Rust executable uses the SDK's version-one framed IPC protocol:
four-byte big-endian JSON length, then UTF-8 JSON; stdout is protocol only. Initialize,
health, invoke, cancellation, and shutdown use `peritus-plugin-sdk`. Peritus uses its
existing native process host with version/digest trust, current authority mediation,
deadlines, and owned-process cleanup. This is a native process, not a stable Rust
dynamic-library ABI, WebAssembly runtime, interpreted recipe, or host-compiled feature.

The `module.workflow` capability carries an outer canonical JSON object containing
`method` and `params_json` (an inner JSON string). Responses contain `json` (an inner
JSON string). This allows normal JSON values, including decimal source metadata,
without changing canonical outer-payload rules. Peritus provides an absolute private
`state_directory` on each call. The plugin owns its durable checkpoints and format.

| Method | Input and effect |
| --- | --- |
| `command` | User-relative `text` and governing `revision`; returns `ModuleAction`. |
| `tool` | Current request `key`, exported function `name`, `arguments_json`; runs plugin Rust code. |
| `observe` | Current `key`, actual host tool `name`, `arguments_json`, `result_json`, `is_error`; lets plugin code retain actual evidence. |
| `model_result` | Current `key`, returned model `text`; plugin decides what happens next. |

`ModuleAction::Reply` presents Markdown, plugin-supplied menu actions, and an optional
explicitly selected text attachment. Actions contain a label, module-relative arguments,
and whether to submit or prepare an editable draft. Menus bind actions to the exact
installed digest and conversation run; they never interpret arguments as shell commands.

`ModuleAction::Model` requests an agent with a durable stage key, writer/reviewer model,
status, system/prompt text, borrowed host tool names, and additional JSON-schema functions
implemented in the native plugin. Peritus owns provider credentials and inference;
plugins reuse current provider selections. Borrowed tools must be declared in the
package and satisfy current host permissions. The initial broker exposes read-only
workspace/web services; plugins can also implement new functionality in their own Rust
functions. Native plugins have the ambient OS authority of the account running Peritus;
the broker is not an OS sandbox.

A successful plugin-defined tool result may include `request_complete: true` to yield
immediately to its coordinator through `model_result` after its durable checkpoint. The
coordinator still validates output; this is not a factual approval. Ordinary borrowed host
web results cannot trigger this handoff.

A module can return an artifact under its private state directory for explicit
conversation/Design reuse. Peritus snapshots its exact bytes by digest and supplies
paged `module_attachment_read`; attaching reference material never starts implementation.

Protocol frames, individual transfers, and short IPC calls have resource bounds.
Agent continuations renew invocation segments while keeping saved memory; there is no
new cumulative research token/time budget. Stop preserves plugin checkpoints; resume
is an explicit plugin command and must respect any feature-specific approval gate.

`ModuleAction::Checkpoint` publishes `{key,text,actions}` without ending the module.
An updated host durably presents the text and menu before invoking `checkpoint_ack` with
that exact key. The module owns the saved publication and the next step. Cancellation or
new user input prevents acknowledgement. A crash between the two steps may replay the
same checkpoint; the contract is at-least-once. This action requires a host implementing
the updated SDK service. Existing Reply/Model modules keep their original behavior.

## Versioned host services

Updated hosts add `host_profile` to each method's `params_json`. It has schema one and an additive
list of `{name, version}` capabilities. `ModuleAction::HostService` carries a durable request key,
capability, exact version, operation, and structured input. The host rechecks current authority and
returns a typed result through `host_result`. `unsupported` means the capability/version/operation is
not implemented and must not be retried as though it were transient.

The current profile advertises capability inspection plus the already implemented private-state,
checkpoint, model, attachment, `module.scoped-source`, and Linux `module.owned-jobs` paths. Scoped source version 1 binds
capture to the explicit opened workspace source, rejects unsafe paths and links, stores immutable
content by digest, and returns revocable opaque handles for manifest and range reads. SDK contracts
`module.owned-jobs@1` provides asynchronous submit, poll, paged log, and cancel operations for
host-selected stable adapters. The first proof adapter runs selected source through the private
Linux backend with cleared environment, deny-all network and secrets, bounded resources, a hidden
host canary, and host-authored receipts. Its separate preparation adapter permits only declared,
digest-pinned HTTPS retrieval through public addresses without credentials and disconnects before
proof. `module.source-build@1` is now advertised on Linux as an inspection-only service for the
running installed module. Build and install authority stays in the host-owned market action; module
code cannot invoke or retry its own compiler. Possessing or serializing any request, handle, job,
or package identity is not authority. Older Reply/Model/Checkpoint modules ignore the additive
input and continue unchanged.

## Source packages

`sources.toml` is an additive schema-one source inventory. Legacy clients continue parsing only
`market.toml`; current clients atomically retain both catalogs at one exact commit. A source entry
pins its canonical tree digest, `Cargo.lock` digest, rustup toolchain, target, Cargo package,
executable, manifest template, and closed recipe identifier. Refresh remains inert.

An explicit Build and install action revalidates the clean commit and all pinned identities,
prepares checksum-bearing crates.io dependencies in a private credential-free cache, and compiles
offline in a bounded Linux systemd/Bubblewrap scope. The host then renders the package manifest,
binds every declared resource and executable byte, and atomically installs the immutable package
outside the repository in the disabled state. Source, archive, recipe, executable, and final
package identities remain distinct in the retained build receipt. Cancellation, failure, or host
loss never publishes partial output or replaces the previously selected package. Retrying is an
explicit new attempt.
