//! Phase-ten managed adapter lifecycle coordinated through the typed host capability.

use crate::{Error, invalid, reply, state, state::PendingRequest};
use peritus_plugin_sdk::{
    HOST_CAPABILITY_WORKER, MODULE_WORKER_FEATURE_BROWSER_AUTOMATION,
    MODULE_WORKER_FEATURE_CARGO_DEPENDENCIES, MODULE_WORKER_FEATURE_JAVASCRIPT_RUNTIME,
    ModuleAction, ModuleAdapterCancelRequest, ModuleAdapterCatalog, ModuleAdapterCompleteRequest,
    ModuleAdapterExecuteRequest, ModuleAdapterExecutionReceipt, ModuleAdapterPhase,
    ModuleAdapterPreparationHandle, ModuleAdapterPrepareRequest, ModuleAdapterRemoveRequest,
    ModuleAdapterRuntimeIdentity, ModuleAdapterStatus, ModuleAdapterStatusRequest,
    ModuleHostProfile, ModuleHostRequest, ModuleWorkerLimits, ModuleWorkerRequest,
};
use serde_json::{Value, json};

pub(crate) const DIAGNOSTIC_ID: &str = "peritus.diagnostic";

pub(crate) fn handles(command: &str) -> bool {
    matches!(
        command,
        "adapters"
            | "adapter-history"
            | "adapter-install diagnostic"
            | "adapter-stage diagnostic"
            | "adapter-complete"
            | "adapter-cancel"
            | "adapter-status"
            | "adapter-remove"
            | "adapter-probe-tampered-metadata"
            | "adapter-probe-wrong-platform"
            | "adapter-probe-unregistered-operation"
    ) || command.starts_with("adapter-run ")
}

pub(crate) fn command(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    command: &str,
) -> Result<ModuleAction, Error> {
    if !supports(profile) {
        return Ok(reply(
            "This Peritus host does not advertise generic isolated module workers. Managed adapters remain blocked; no ambient executable or command fallback was attempted.",
            profile,
            super::actions(state),
            None,
        ));
    }
    match command {
        "adapters" => request_catalog(parameters, state, false, false, None),
        "adapter-history" => Ok(reply(view(state), profile, super::actions(state), None)),
        "adapter-install diagnostic" => {
            request_catalog(parameters, state, true, true, Some(DIAGNOSTIC_ID.into()))
        }
        "adapter-stage diagnostic" => {
            request_catalog(parameters, state, true, false, Some(DIAGNOSTIC_ID.into()))
        }
        "adapter-complete" => {
            let preparation = state
                .adapter_preparation
                .as_ref()
                .ok_or_else(|| invalid("no staged adapter preparation is retained"))?;
            let request = ModuleAdapterCompleteRequest {
                schema: 1,
                preparation_id: preparation.preparation_id.clone(),
            };
            service(
                parameters,
                state,
                PendingRequest::AdapterComplete { key: next_key(state, "complete"), request },
                "complete",
            )
        }
        "adapter-cancel" => {
            let preparation = state
                .adapter_preparation
                .as_ref()
                .ok_or_else(|| invalid("no staged adapter preparation is retained"))?;
            let request = ModuleAdapterCancelRequest {
                schema: 1,
                preparation_id: preparation.preparation_id.clone(),
                reason: "user requested cancellation before installation".into(),
            };
            service(
                parameters,
                state,
                PendingRequest::AdapterCancel { key: next_key(state, "cancel"), request },
                "cancel",
            )
        }
        "adapter-status" => {
            let request =
                ModuleAdapterStatusRequest { schema: 1, adapter_id: DIAGNOSTIC_ID.into() };
            service(
                parameters,
                state,
                PendingRequest::AdapterStatus { key: next_key(state, "status"), request },
                "status",
            )
        }
        "adapter-remove" => {
            let runtime = installed_runtime(state, DIAGNOSTIC_ID)
                .ok_or_else(|| invalid("no installed diagnostic runtime is retained"))?;
            let request = ModuleAdapterRemoveRequest { schema: 1, runtime };
            service(
                parameters,
                state,
                PendingRequest::AdapterRemove { key: next_key(state, "remove"), request },
                "remove",
            )
        }
        "adapter-probe-tampered-metadata" | "adapter-probe-wrong-platform" => {
            let mut descriptor = state
                .adapter_catalog
                .as_ref()
                .and_then(|catalog| {
                    catalog
                        .descriptors
                        .iter()
                        .find(|descriptor| descriptor.adapter_id == DIAGNOSTIC_ID)
                })
                .cloned()
                .ok_or_else(|| {
                    invalid("read the adapter catalog before probing descriptor rejection")
                })?;
            if command.ends_with("wrong-platform") {
                descriptor.platform.os = "not-this-host".into();
            } else {
                descriptor.version = "tampered-version".into();
            }
            let request = ModuleAdapterPrepareRequest { schema: 1, descriptor };
            service(
                parameters,
                state,
                PendingRequest::AdapterPrepare {
                    key: next_key(state, "rejection"),
                    request,
                    complete_after: false,
                },
                "prepare",
            )
        }
        "adapter-probe-unregistered-operation" => {
            let runtime = installed_runtime(state, DIAGNOSTIC_ID).ok_or_else(|| {
                invalid("install the diagnostic adapter before probing operation rejection")
            })?;
            let request = ModuleAdapterExecuteRequest {
                schema: 1,
                runtime,
                operation: "diagnostic.not-registered.v1".into(),
                input: json!({"message":"must not execute"}),
            };
            service(
                parameters,
                state,
                PendingRequest::AdapterExecute { key: next_key(state, "rejection"), request },
                "execute",
            )
        }
        _ => {
            let message = command
                .strip_prefix("adapter-run ")
                .ok_or_else(|| invalid("unknown adapter command"))?;
            if message.trim().is_empty() {
                return Err(invalid("adapter-run requires a diagnostic message"));
            }
            let runtime = installed_runtime(state, DIAGNOSTIC_ID)
                .ok_or_else(|| invalid("install the diagnostic adapter before executing it"))?;
            let request = ModuleAdapterExecuteRequest {
                schema: 1,
                runtime,
                operation: "diagnostic.echo.v1".into(),
                input: json!({"message": message}),
            };
            service(
                parameters,
                state,
                PendingRequest::AdapterExecute { key: next_key(state, "execute"), request },
                "execute",
            )
        }
    }
}

pub(crate) fn admit(
    parameters: &Value,
    profile: &Option<ModuleHostProfile>,
    state: &mut state::State,
    pending: PendingRequest,
    output: Value,
) -> Result<ModuleAction, Error> {
    let text = match pending {
        PendingRequest::AdapterCatalog { install_after, complete_after, adapter_id, .. } => {
            let catalog: ModuleAdapterCatalog = serde_json::from_value(output)?;
            if catalog.schema != 1 {
                return Err(invalid("unsupported adapter catalog schema"));
            }
            state.adapter_catalog = Some(catalog.clone());
            state.pending = None;
            if install_after {
                let adapter_id = adapter_id.as_deref().ok_or_else(|| {
                    invalid("adapter installation is missing its registry identity")
                })?;
                let descriptor = catalog
                    .descriptors
                    .iter()
                    .find(|descriptor| descriptor.adapter_id == adapter_id)
                    .cloned()
                    .ok_or_else(|| invalid("host catalog has no requested adapter"))?;
                let request = ModuleAdapterPrepareRequest { schema: 1, descriptor };
                return service(
                    parameters,
                    state,
                    PendingRequest::AdapterPrepare {
                        key: next_key(state, "prepare"),
                        request,
                        complete_after,
                    },
                    "prepare",
                );
            }
            catalog_text(&catalog)
        }
        PendingRequest::AdapterPrepare { complete_after, .. } => {
            let handle: ModuleAdapterPreparationHandle = serde_json::from_value(output)?;
            state.adapter_preparation = Some(handle.clone());
            state.pending = None;
            if complete_after {
                let request = ModuleAdapterCompleteRequest {
                    schema: 1,
                    preparation_id: handle.preparation_id,
                };
                return service(
                    parameters,
                    state,
                    PendingRequest::AdapterComplete { key: next_key(state, "complete"), request },
                    "complete",
                );
            }
            format!(
                "# Adapter staged\n\n- Preparation: `{}`\n- Descriptor: `{}`\n\nThe exact registered bytes are staged but cannot execute. Use `adapter-complete` or `adapter-cancel`.",
                handle.preparation_id, handle.descriptor_digest
            )
        }
        PendingRequest::AdapterComplete { .. }
        | PendingRequest::AdapterCancel { .. }
        | PendingRequest::AdapterStatus { .. }
        | PendingRequest::AdapterRemove { .. } => {
            let status: ModuleAdapterStatus = serde_json::from_value(output)?;
            state.adapter_statuses.push(status.clone());
            if matches!(status.phase, ModuleAdapterPhase::Cancelled | ModuleAdapterPhase::Removed) {
                state.adapter_preparation = None;
            }
            status_text(&status)
        }
        PendingRequest::AdapterExecute { .. } => {
            let receipt: ModuleAdapterExecutionReceipt = serde_json::from_value(output)?;
            state.adapter_receipts.push(receipt.clone());
            if receipt.operation == crate::source_analysis::OPERATION {
                return crate::source_analysis::admit(parameters, profile, state, receipt);
            }
            if receipt.operation == crate::http_api::OPERATION {
                return crate::http_api::admit(parameters, profile, state, receipt);
            }
            if receipt.operation == crate::browser_client::OPERATION {
                return crate::browser_client::admit(parameters, profile, state, receipt);
            }
            if receipt.operation == crate::identity_access::OPERATION {
                return crate::identity_access::admit(parameters, profile, state, receipt);
            }
            if receipt.operation == crate::file_fuzz::OPERATION {
                return crate::file_fuzz::admit(parameters, profile, state, receipt);
            }
            if receipt.operation == crate::workflow_state::OPERATION {
                return crate::workflow_state::admit(parameters, profile, state, receipt);
            }
            if receipt.operation == crate::boundary_authority::OPERATION {
                return crate::boundary_authority::admit(parameters, profile, state, receipt);
            }
            if receipt.operation == crate::attack_graph::OPERATION {
                return crate::attack_graph::admit(parameters, profile, state, receipt);
            }
            if receipt.operation == crate::diamond_binding::OPERATION {
                return crate::diamond_binding::admit(parameters, profile, state, receipt);
            }
            if receipt.operation == crate::application_binding::OPERATION {
                return crate::application_binding::admit(parameters, profile, state, receipt);
            }
            format!(
                "# Diagnostic adapter receipt\n\n- Runtime: `{}`\n- Operation: `{}`\n- Input digest: `{}`\n- Receipt decoder: `{}`\n- Executed by: `{}`\n\n```json\n{}\n```",
                receipt.runtime_digest,
                receipt.operation,
                receipt.input_digest,
                receipt.receipt_decoder,
                receipt.executed_by,
                serde_json::to_string_pretty(&receipt.observation)?,
            )
        }
        _ => return Err(invalid("non-adapter pending request reached adapter admission")),
    };
    state.pending = None;
    state::save(parameters, state)?;
    if state.application_campaign_pending
        && state.investigation.stage == state::InvestigationStage::Probing
        && installed_runtime(state, crate::application_binding::ADAPTER_ID).is_some()
    {
        return crate::investigation::next(parameters, profile, state);
    }
    Ok(reply(text, profile, super::actions(state), None))
}

pub(crate) fn view(state: &state::State) -> String {
    let catalog = state.adapter_catalog.as_ref().map(catalog_text).unwrap_or_else(|| {
        "# Managed adapters\n\nCatalog not observed yet. Use `adapters`.".into()
    });
    let latest = state
        .adapter_statuses
        .last()
        .map(status_text)
        .unwrap_or_else(|| "No retained lifecycle status.".into());
    let errors = if state.adapter_errors.is_empty() {
        "none".into()
    } else {
        state.adapter_errors.iter().map(|error| format!("- {error}")).collect::<Vec<_>>().join("\n")
    };
    format!(
        "{catalog}\n\n## Latest lifecycle status\n\n{latest}\n\n## Module-authored execution receipts\n\n{}\n\n## Retained errors\n\n{errors}",
        state.adapter_receipts.len()
    )
}

pub(crate) fn supports(profile: &Option<ModuleHostProfile>) -> bool {
    profile.as_ref().is_some_and(|profile| profile.supports(HOST_CAPABILITY_WORKER, 1))
}

fn request_catalog(
    parameters: &Value,
    state: &mut state::State,
    install_after: bool,
    complete_after: bool,
    adapter_id: Option<String>,
) -> Result<ModuleAction, Error> {
    let pending = PendingRequest::AdapterCatalog {
        key: next_key(state, "catalog"),
        install_after,
        complete_after,
        adapter_id,
    };
    service(parameters, state, pending, "catalog")
}

fn service(
    parameters: &Value,
    state: &mut state::State,
    pending: PendingRequest,
    operation: &str,
) -> Result<ModuleAction, Error> {
    let input = match &pending {
        PendingRequest::AdapterCatalog { .. } => json!({}),
        PendingRequest::AdapterPrepare { request, .. } => serde_json::to_value(request)?,
        PendingRequest::AdapterComplete { request, .. } => serde_json::to_value(request)?,
        PendingRequest::AdapterCancel { request, .. } => serde_json::to_value(request)?,
        PendingRequest::AdapterStatus { request, .. } => serde_json::to_value(request)?,
        PendingRequest::AdapterRemove { request, .. } => serde_json::to_value(request)?,
        PendingRequest::AdapterExecute { request, .. } => serde_json::to_value(request)?,
        _ => return Err(invalid("non-adapter request reached adapter service")),
    };
    let key = pending.key().to_owned();
    let source = state
        .active_handle()
        .ok_or_else(|| invalid("capture source before using a Red Team module worker"))?;
    let source_snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("capture source before using a Red Team module worker"))?
        .snapshot_digest
        .clone();
    let runtime_features = worker_runtime_features(&pending);
    let limits = worker_limits(&runtime_features);
    state.pending = Some(pending);
    state::save(parameters, state)?;
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key: key.clone(),
            capability: HOST_CAPABILITY_WORKER.into(),
            version: 1,
            operation: "execute".into(),
            input: serde_json::to_value(ModuleWorkerRequest {
                schema: 1,
                source,
                worker: "adapter-runtime".into(),
                input: json!({
                    "request_key": key,
                    "operation": operation,
                    "request": input,
                    "source_snapshot": source_snapshot,
                    "targets": state.runtime_targets,
                }),
                runtime_features,
                limits,
            })?,
        },
    })
}

pub(crate) fn resume_worker(
    state: &state::State,
    pending: &PendingRequest,
) -> Result<ModuleAction, Error> {
    let (operation, input) = match pending {
        PendingRequest::AdapterCatalog { .. } => ("catalog", json!({})),
        PendingRequest::AdapterPrepare { request, .. } => {
            ("prepare", serde_json::to_value(request)?)
        }
        PendingRequest::AdapterComplete { request, .. } => {
            ("complete", serde_json::to_value(request)?)
        }
        PendingRequest::AdapterCancel { request, .. } => ("cancel", serde_json::to_value(request)?),
        PendingRequest::AdapterStatus { request, .. } => ("status", serde_json::to_value(request)?),
        PendingRequest::AdapterRemove { request, .. } => ("remove", serde_json::to_value(request)?),
        PendingRequest::AdapterExecute { request, .. } => {
            ("execute", serde_json::to_value(request)?)
        }
        _ => return Err(invalid("non-adapter request reached adapter worker resume")),
    };
    let source = state
        .active_handle()
        .ok_or_else(|| invalid("captured source authority is unavailable for worker resume"))?;
    let source_snapshot = state
        .active_snapshot()
        .ok_or_else(|| invalid("captured source snapshot is unavailable for worker resume"))?
        .snapshot_digest
        .clone();
    let runtime_features = worker_runtime_features(pending);
    let limits = worker_limits(&runtime_features);
    Ok(ModuleAction::HostService {
        request: ModuleHostRequest {
            key: pending.key().to_owned(),
            capability: HOST_CAPABILITY_WORKER.into(),
            version: 1,
            operation: "execute".into(),
            input: serde_json::to_value(ModuleWorkerRequest {
                schema: 1,
                source,
                worker: "adapter-runtime".into(),
                input: json!({
                    "request_key": pending.key(),
                    "operation": operation,
                    "request": input,
                    "source_snapshot": source_snapshot,
                    "targets": state.runtime_targets,
                }),
                runtime_features,
                limits,
            })?,
        },
    })
}

fn worker_runtime_features(pending: &PendingRequest) -> Vec<String> {
    let PendingRequest::AdapterExecute { request, .. } = pending else {
        return Vec::new();
    };
    match request.runtime.adapter_id.as_str() {
        crate::diamond_binding::ADAPTER_ID => vec![
            MODULE_WORKER_FEATURE_BROWSER_AUTOMATION.into(),
            MODULE_WORKER_FEATURE_CARGO_DEPENDENCIES.into(),
        ],
        crate::application_binding::ADAPTER_ID => {
            vec![
                MODULE_WORKER_FEATURE_BROWSER_AUTOMATION.into(),
                MODULE_WORKER_FEATURE_JAVASCRIPT_RUNTIME.into(),
            ]
        }
        crate::browser_client::ADAPTER_ID | crate::attack_graph::ADAPTER_ID => {
            vec![MODULE_WORKER_FEATURE_BROWSER_AUTOMATION.into()]
        }
        _ => Vec::new(),
    }
}

fn worker_limits(runtime_features: &[String]) -> ModuleWorkerLimits {
    let browser_automation =
        runtime_features.iter().any(|feature| feature == MODULE_WORKER_FEATURE_BROWSER_AUTOMATION);
    ModuleWorkerLimits {
        wall_millis: 300_000,
        // Browser workers need a larger resident-memory ceiling than the ordinary adapters.
        memory_bytes: if browser_automation { 2 * 1024 * 1024 * 1024 } else { 1024 * 1024 * 1024 },
        storage_bytes: 2 * 1024 * 1024 * 1024,
        // Linux accounts Chromium's helper processes and threads against the same pids cgroup.
        // Leave ordinary adapters tightly bounded, while allowing the browser engine enough
        // headroom to initialize and execute the retained campaign under the 2 GiB memory cap.
        processes: if browser_automation { 512 } else { 64 },
        open_handles: if browser_automation { 1_024 } else { 64 },
    }
}

pub(crate) fn installed_runtime(
    state: &state::State,
    adapter_id: &str,
) -> Option<ModuleAdapterRuntimeIdentity> {
    state
        .adapter_statuses
        .iter()
        .rev()
        .find(|status| status.adapter_id == adapter_id)
        .filter(|status| status.phase == ModuleAdapterPhase::Installed)
        .and_then(|status| status.runtime.clone())
}

pub(crate) fn install(
    parameters: &Value,
    state: &mut state::State,
    adapter_id: &str,
) -> Result<ModuleAction, Error> {
    request_catalog(parameters, state, true, true, Some(adapter_id.into()))
}

pub(crate) fn status_for(
    parameters: &Value,
    state: &mut state::State,
    adapter_id: &str,
) -> Result<ModuleAction, Error> {
    let request = ModuleAdapterStatusRequest { schema: 1, adapter_id: adapter_id.into() };
    service(
        parameters,
        state,
        PendingRequest::AdapterStatus { key: next_key(state, "status"), request },
        "status",
    )
}

pub(crate) fn remove_for(
    parameters: &Value,
    state: &mut state::State,
    adapter_id: &str,
) -> Result<ModuleAction, Error> {
    let runtime = installed_runtime(state, adapter_id)
        .ok_or_else(|| invalid("the requested adapter has no installed runtime"))?;
    let request = ModuleAdapterRemoveRequest { schema: 1, runtime };
    service(
        parameters,
        state,
        PendingRequest::AdapterRemove { key: next_key(state, "remove"), request },
        "remove",
    )
}

pub(crate) fn execute(
    parameters: &Value,
    state: &mut state::State,
    request: ModuleAdapterExecuteRequest,
) -> Result<ModuleAction, Error> {
    service(
        parameters,
        state,
        PendingRequest::AdapterExecute { key: next_key(state, "execute"), request },
        "execute",
    )
}

fn next_key(state: &state::State, operation: &str) -> String {
    format!(
        "red-team-adapter-{operation}-{}",
        state.adapter_statuses.len()
            + state.adapter_receipts.len()
            + state.adapter_errors.len()
            + 1
    )
}

fn catalog_text(catalog: &ModuleAdapterCatalog) -> String {
    let mut text = "# Managed adapter catalog\n\n".to_string();
    for descriptor in &catalog.descriptors {
        text.push_str(&format!(
            "- `{}` {} — {}/{} — artifact `{}` ({} bytes) — decoder `{}`\n",
            descriptor.adapter_id,
            descriptor.version,
            descriptor.platform.os,
            descriptor.platform.architecture,
            descriptor.artifact_digest,
            descriptor.artifact_bytes,
            descriptor.receipt_decoder,
        ));
        for operation in &descriptor.operations {
            text.push_str(&format!(
                "  - `{}` — input `{}` — receipt `{}`\n",
                operation.name, operation.input_schema, operation.receipt_schema
            ));
        }
    }
    text
}

fn status_text(status: &ModuleAdapterStatus) -> String {
    let runtime = status.runtime.as_ref().map_or("none", |runtime| runtime.runtime_digest.as_str());
    let provenance =
        status.provenance.as_ref().map_or("none", |receipt| receipt.descriptor_digest.as_str());
    format!(
        "# Managed adapter status\n\n- Adapter: `{}`\n- Phase: `{:?}`\n- Preparation: `{}`\n- Runtime: `{runtime}`\n- Provenance descriptor: `{provenance}`\n- Reused: {}\n- Detail: {}\n- Retained error: {}",
        status.adapter_id,
        status.phase,
        status.preparation_id.as_deref().unwrap_or("none"),
        status.reused,
        status.detail,
        status.retained_error.as_deref().unwrap_or("none"),
    )
}
