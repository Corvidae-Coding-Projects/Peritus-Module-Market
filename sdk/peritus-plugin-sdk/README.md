# Native Peritus Rust plugin SDK

This directory contains the compatible `peritus-plugin-sdk` Rust source from
Project-Peritus, under the repository MIT license. It is included so the market
workspace builds independently of a Peritus checkout. The source matches the host's
framed IPC contracts, including the generic native module service in `src/module.rs`.

Use `PluginRequestEnvelope`, `PluginResponseEnvelope`, `decode_frame`, `encode_frame`,
and `ModuleAction`. The SDK contains contracts and framing; feature code belongs in
the native module crate. Decoding a request does not grant authority. The native host
checks exact executable/package identity, current host-service permissions, and lifecycle.
Native processes retain ambient OS account authority.

See [CATALOG.md](../../CATALOG.md) for services and
[the native Rust template](../../templates/rust-plugin/README.md) for executable code.

Updated hosts also support `ModuleAction::Checkpoint { key, text, actions }`. The host
retains the publication and current menu before calling `checkpoint_ack` with the exact
key, allowing continuing work with visible results. Cancellation/new steering prevents
acknowledgement. A crash between publication and acknowledgement can replay the same
checkpoint. Plugins using this additive service require a host that implements it; old
Reply/Model plugins continue unchanged.
