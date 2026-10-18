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
